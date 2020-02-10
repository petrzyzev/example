# frozen_string_literal: true

require_relative 'errors'

module Ldap
  # Класс проверки корректности введенных пользователем данных
  class UserCheck
    # Объект соединения
    # @return [Net::Ldap]
    #   объект, позволяющий произвести операции
    #   c Active Directory
    attr_reader :connection

    # Имя пользователя
    # @return [String]
    #   введенное имя пользователя
    attr_reader :username

    # Пароль пользователя
    # @return [String]
    #   введенный пароль пользователя
    attr_reader :password

    # Инициализирует объект класса проверки
    # @param [Net::Ldap] connection
    #   объект, позволяющий произвести операции
    #   c Active Directory
    # @param [Hash] credentials
    #   хэш, содержащий в себе информацию
    #   о введенных пользователем данных
    def initialize(connection, credentials)
      @connection = connection
      @username = credentials[:username]
      @password = credentials[:password]
    end

    # Создает экземпляр класса [Ldap::UserCheck]
    # и проверяет данные, введенные пользователем
    # @param [Net::Ldap] connection
    #   объект, позволяющий произвести операции
    #   c Active Directory
    # @param [Hash] credentials
    #   хэш, содержащий в себе информацию
    #   о введенных пользователем данных
    def self.call(connection, credentials)
      new(connection, credentials).check_user
    end

    # Проверяет введенные пользователем данные
    # @raise [Ldap::NotFoundInADError]
    #   если пользователь с введенным логином
    #   не найден в Active Directory
    # @raise (see #check_user_account)
    def check_user
      raise NotFoundInADError, username unless found_user?

      check_user_account unless user_authorized?
    end

    # Индекс символа, по которому проверяется наличие флага на свойстве
    # "ACCOUNTDISABLE" в бинарном значении атрибута "UserAccountControl"
    # учетной записи пользователя
    ACCOUNT_DISABLE = 1

    # Проверяет атрибуты учётной записи
    # @raise [Ldap::WrongPasswordError]
    #   если введен неверный пароль пользователя
    # @raise [Ldap::ExpiredPasswordError]
    #   если истек срок действия пароля
    # @raise [Ldap::DisableAccountError]
    #   если учетная запись отключена
    # @raise [Ldap::LockoutAccountError]
    #   если учётная запись заблокирована
    # @raise [Ldap::NotAuthorizedError]
    #   если проблема авторизации не попадает под
    #   вышеперечисленные случаи
    def check_user_account
      raise WrongPasswordError, username if wrong_password?
      raise DisableAccountError, username if property_active?(ACCOUNT_DISABLE)
      raise LockoutAccountError, username if account_lockout?
      raise ExpiredPasswordError, username if password_expired?

      raise NotAuthorizedError, username
    end

    # Ищет пользователя в Active Directory
    # @return [Boolean]
    #   найден ли пользователь
    def found_user?
      founded_user.any?
    end

    # Производит попытку авторизоваться в Active Directory
    # с указанными данными
    # @return [Boolean]
    #   в случае, если попытка неудачна
    # @return [Object]
    #   в случае, если попытка удачна
    def user_authorized?
      connection.bind_as(filter: connection_filter, password: password)
    end

    # Максимальное количество попыток ввести пароль, после которых
    # учётная запись блокируется
    MAX_ATTEMPTS_COUNT = 20

    # Проверяет, заблокирована ли учётная запись
    # @return [Boolean]
    #   заблокирована ли учётная запись
    def account_lockout?
      num_user_attribute(:badpwdcount) == MAX_ATTEMPTS_COUNT
    end

    # Проверяет, является ли введенный пользователем пароль неверным
    # @return [Boolean]
    #   верный ли пароль
    def wrong_password?
      first_bad_pwd_count = num_user_attribute(:badpwdcount)
      @founded_user = nil
      second_bad_pwd_count = num_user_attribute(:badpwdcount)
      second_bad_pwd_count > first_bad_pwd_count
    end

    # Индекс символа, по которому проверяется наличие
    # флага на свойстве "DONT_EXPIRE_PASSWORD" в бинарном
    # значении атрибута "UserAccountControl" учетной записи пользователя
    PWD_NOT_EXPIRED_NUMBER = 16

    # Проверяет введенный пользователем пароль на истечение срока действия
    # @return [Boolean]
    #   просрочен ли пароль
    def password_expired?
      # Извлечение из учетной записи пользователя времени создания пароля.
      # Если срок действия пароля не истек, значение переменной будет
      # равно времени (в формате LDAP Timestamp), иначе "0"
      password_create_time = num_user_attribute(:pwdlastset)
      password_create_time.zero? && !property_active?(PWD_NOT_EXPIRED_NUMBER)
    end

    # Проверяет, активно ли свойство атрибута UserAccountControl
    # учетной записи Active Directory, путем проверки бинарного представления
    # числа данного атрибута
    # @param [Integer] property_index
    #   индекс флага свойства в числе атрибута
    # @return [Boolean]
    #   активно ли свойство
    def property_active?(property_index)
      account_control.to_s(2).reverse[property_index].to_i == 1
    end

    # Извлекает из учетной записи пользователя первый элемент атрибута `name`
    # и конвертирует его в числовое представление
    # @param [Symbol] name
    #   название атрибута
    # @return [Integer]
    #   числовое представление значения атрибута `name`
    def num_user_attribute(name)
      founded_user.first[name][0].to_i
    end

    # Извлекает атрибут UserAccountControl учетной записи.
    # Возвращаемое значение является суммой десятичных чисел
    # свойств учетной записи (см. Active Directory: UserAccountControl)
    # @return [Integer]
    #   значение атрибута UserAccountControl
    def account_control
      @account_control ||= num_user_attribute(:useraccountcontrol)
    end

    # Возвращает значение параметра фильтрации для поиска
    # пользователя в Active Directory
    # @return [String]
    #   значение параметра фильтрации
    def connection_filter
      @connection_filter ||= "(sAMAccountName=#{username})"
    end

    # Возвращает найденного пользователя
    # @return [Array]
    #   массив с найденной учётной записью
    def founded_user
      @founded_user ||= connection.search(filter: connection_filter)
    end
  end
end
