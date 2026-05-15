//
//  Configuration.swift
//  (c) 2024 Firezone, Inc.
//  LICENSE: Apache-2.0
//
//  App configuration facade.
//
//  User-edited values are persisted in the VPN provider configuration. MDM-managed
//  values remain in UserDefaults and override the provider values only when forced.

import Combine
import Foundation

enum ConfigurationDefaults {
  #if DEBUG
    static let authURL = "https://app.firez.one"
    static let apiURL = "wss://api.firez.one"
    static let logFilter = "debug"
  #else
    static let authURL = "https://app.firezone.dev"
    static let apiURL = "wss://api.firezone.dev"
    static let logFilter = "info"
  #endif

  static let accountSlug = ""
  static let actorName = "Unknown user"
  static let supportURL = "https://www.firezone.dev/support"
  static let connectOnStart = false
  static let startOnLogin = false
  static let disableUpdateCheck = false
  static let internetResourceEnabled = false
}

enum ConfigurationValue {
  static func bool(_ value: String?, default defaultValue: Bool) -> Bool {
    switch value {
    case "true":
      return true
    case "false":
      return false
    default:
      return defaultValue
    }
  }

  static func string(_ value: Bool) -> String {
    value ? "true" : "false"
  }
}

@MainActor
public class Configuration: ObservableObject {
  static let shared = Configuration()
  private var cancellables = Set<AnyCancellable>()

  @Published private(set) var publishedInternetResourceEnabled = false
  @Published private(set) var publishedHideAdminPortalMenuItem = false
  @Published private(set) var publishedHideResourceList = false

  var isAuthURLForced: Bool { defaults.objectIsForced(forKey: Keys.authURL) }
  var isApiURLForced: Bool { defaults.objectIsForced(forKey: Keys.apiURL) }
  var isLogFilterForced: Bool { defaults.objectIsForced(forKey: Keys.logFilter) }
  var isAccountSlugForced: Bool { defaults.objectIsForced(forKey: Keys.accountSlug) }
  var isConnectOnStartForced: Bool { defaults.objectIsForced(forKey: Keys.connectOnStart) }
  var isStartOnLoginForced: Bool { defaults.objectIsForced(forKey: Keys.startOnLogin) }
  var isInternetResourceEnabledForced: Bool {
    defaults.objectIsForced(forKey: Keys.internetResourceEnabled)
  }

  var authURL: String {
    get { effectiveString(forKey: Keys.authURL, default: ConfigurationDefaults.authURL) }
    set { setProviderValue(newValue, forKey: Keys.authURL) }
  }

  var apiURL: String {
    get { effectiveString(forKey: Keys.apiURL, default: ConfigurationDefaults.apiURL) }
    set { setProviderValue(newValue, forKey: Keys.apiURL) }
  }

  var logFilter: String {
    get { effectiveString(forKey: Keys.logFilter, default: ConfigurationDefaults.logFilter) }
    set { setProviderValue(newValue, forKey: Keys.logFilter) }
  }

  var accountSlug: String {
    get { effectiveString(forKey: Keys.accountSlug, default: ConfigurationDefaults.accountSlug) }
    set { setProviderValue(newValue, forKey: Keys.accountSlug) }
  }

  var actorName: String {
    get { providerString(forKey: Keys.actorName, default: ConfigurationDefaults.actorName) }
    set { setProviderValue(newValue, forKey: Keys.actorName) }
  }

  var hideAdminPortalMenuItem: Bool {
    forcedBool(forKey: Keys.hideAdminPortalMenuItem, default: false)
  }

  var hideResourceList: Bool {
    forcedBool(forKey: Keys.hideResourceList, default: false)
  }

  var connectOnStart: Bool {
    get {
      effectiveBool(
        forKey: Keys.connectOnStart,
        default: ConfigurationDefaults.connectOnStart
      )
    }
    set { setProviderValue(newValue, forKey: Keys.connectOnStart) }
  }

  var startOnLogin: Bool {
    get {
      effectiveBool(
        forKey: Keys.startOnLogin,
        default: ConfigurationDefaults.startOnLogin
      )
    }
    set { setProviderValue(newValue, forKey: Keys.startOnLogin) }
  }

  var disableUpdateCheck: Bool {
    forcedBool(forKey: Keys.disableUpdateCheck, default: ConfigurationDefaults.disableUpdateCheck)
  }

  var supportURL: String {
    forcedString(forKey: Keys.supportURL) ?? ConfigurationDefaults.supportURL
  }

  var internetResourceEnabled: Bool {
    get {
      effectiveBool(
        forKey: Keys.internetResourceEnabled,
        default: ConfigurationDefaults.internetResourceEnabled
      )
    }
    set { setProviderValue(newValue, forKey: Keys.internetResourceEnabled) }
  }

  enum Keys {
    static let authURL = "authURL"
    static let apiURL = "apiURL"
    static let logFilter = "logFilter"
    static let accountSlug = "accountSlug"
    static let actorName = "actorName"
    static let internetResourceEnabled = "internetResourceEnabled"
    static let hideAdminPortalMenuItem = "hideAdminPortalMenuItem"
    static let hideResourceList = "hideResourceList"
    static let connectOnStart = "connectOnStart"
    static let startOnLogin = "startOnLogin"
    static let disableUpdateCheck = "disableUpdateCheck"
    static let supportURL = "supportURL"
    static let userDefaultsMigrated = "userDefaultsMigrated"
  }

  private var defaults: UserDefaults
  private var providerConfiguration: [String: String]

  // swiftlint:disable:next no_userdefaults_standard - DI entry point
  init(userDefaults: UserDefaults = UserDefaults.standard) {
    defaults = userDefaults
    providerConfiguration = [:]

    self.publishedInternetResourceEnabled = internetResourceEnabled
    self.publishedHideAdminPortalMenuItem = hideAdminPortalMenuItem
    self.publishedHideResourceList = hideResourceList

    NotificationCenter.default.publisher(for: UserDefaults.didChangeNotification, object: defaults)
      .receive(on: DispatchQueue.main)
      .sink { [weak self] _ in
        self?.handleUserDefaultsChanged()
      }
      .store(in: &cancellables)
  }

  func toTunnelConfiguration() -> TunnelConfiguration {
    return TunnelConfiguration(
      apiURL: apiURL,
      accountSlug: accountSlug,
      logFilter: logFilter,
      internetResourceEnabled: internetResourceEnabled
    )
  }

  func loadProviderConfiguration(
    _ providerConfiguration: [String: String],
    migrateUserDefaults: Bool
  ) {
    var providerConfiguration = providerConfiguration

    if migrateUserDefaults {
      migrateLegacyUserDefaults(into: &providerConfiguration)
    }

    guard self.providerConfiguration != providerConfiguration else {
      handleConfigurationChanged()
      return
    }

    self.providerConfiguration = providerConfiguration
    handleConfigurationChanged()
  }

  func toProviderConfiguration(
    markUserDefaultsMigrated: Bool = true
  ) -> [String: String] {
    var providerConfiguration = [
      Keys.authURL: providerString(forKey: Keys.authURL, default: ConfigurationDefaults.authURL),
      Keys.apiURL: providerString(forKey: Keys.apiURL, default: ConfigurationDefaults.apiURL),
      Keys.logFilter: providerString(
        forKey: Keys.logFilter,
        default: ConfigurationDefaults.logFilter
      ),
      Keys.accountSlug: providerString(
        forKey: Keys.accountSlug,
        default: ConfigurationDefaults.accountSlug
      ),
      Keys.actorName: providerString(
        forKey: Keys.actorName,
        default: ConfigurationDefaults.actorName
      ),
      Keys.connectOnStart: ConfigurationValue.string(
        providerBool(
          forKey: Keys.connectOnStart,
          default: ConfigurationDefaults.connectOnStart
        )
      ),
      Keys.startOnLogin: ConfigurationValue.string(
        providerBool(
          forKey: Keys.startOnLogin,
          default: ConfigurationDefaults.startOnLogin
        )
      ),
      Keys.internetResourceEnabled: ConfigurationValue.string(
        providerBool(
          forKey: Keys.internetResourceEnabled,
          default: ConfigurationDefaults.internetResourceEnabled
        )
      ),
    ]

    if markUserDefaultsMigrated {
      providerConfiguration[Keys.userDefaultsMigrated] = "true"
    }

    return providerConfiguration
  }

  static func defaultProviderConfiguration(markUserDefaultsMigrated: Bool) -> [String: String] {
    var providerConfiguration = [
      Keys.authURL: ConfigurationDefaults.authURL,
      Keys.apiURL: ConfigurationDefaults.apiURL,
      Keys.logFilter: ConfigurationDefaults.logFilter,
      Keys.accountSlug: ConfigurationDefaults.accountSlug,
      Keys.actorName: ConfigurationDefaults.actorName,
      Keys.connectOnStart: ConfigurationValue.string(ConfigurationDefaults.connectOnStart),
      Keys.startOnLogin: ConfigurationValue.string(ConfigurationDefaults.startOnLogin),
      Keys.internetResourceEnabled: ConfigurationValue.string(
        ConfigurationDefaults.internetResourceEnabled
      ),
    ]

    if markUserDefaultsMigrated {
      providerConfiguration[Keys.userDefaultsMigrated] = "true"
    }

    return providerConfiguration
  }

  private func effectiveString(forKey key: String, default defaultValue: String) -> String {
    forcedString(forKey: key) ?? providerString(forKey: key, default: defaultValue)
  }

  private func providerString(forKey key: String, default defaultValue: String) -> String {
    providerConfiguration[key] ?? defaultValue
  }

  private func forcedString(forKey key: String) -> String? {
    guard defaults.objectIsForced(forKey: key) else { return nil }
    return defaults.string(forKey: key)
  }

  private func effectiveBool(forKey key: String, default defaultValue: Bool) -> Bool {
    forcedBool(
      forKey: key,
      default: providerBool(forKey: key, default: defaultValue)
    )
  }

  private func providerBool(forKey key: String, default defaultValue: Bool) -> Bool {
    ConfigurationValue.bool(providerConfiguration[key], default: defaultValue)
  }

  private func forcedBool(forKey key: String, default defaultValue: Bool) -> Bool {
    guard defaults.objectIsForced(forKey: key) else { return defaultValue }
    return defaults.bool(forKey: key)
  }

  private func setProviderValue(_ value: String, forKey key: String) {
    guard providerConfiguration[key] != value else { return }
    providerConfiguration[key] = value
    handleConfigurationChanged()
  }

  private func setProviderValue(_ value: Bool, forKey key: String) {
    setProviderValue(ConfigurationValue.string(value), forKey: key)
  }

  private func migrateLegacyUserDefaults(into providerConfiguration: inout [String: String]) {
    migrateLegacyString(Keys.authURL, into: &providerConfiguration)
    migrateLegacyString(Keys.apiURL, into: &providerConfiguration)
    migrateLegacyString(Keys.logFilter, into: &providerConfiguration)
    migrateLegacyString(Keys.accountSlug, into: &providerConfiguration)
    migrateLegacyString(Keys.actorName, into: &providerConfiguration)
    migrateLegacyBool(Keys.connectOnStart, into: &providerConfiguration)
    migrateLegacyBool(Keys.startOnLogin, into: &providerConfiguration)
    migrateLegacyBool(Keys.internetResourceEnabled, into: &providerConfiguration)
  }

  private func migrateLegacyString(
    _ key: String, into providerConfiguration: inout [String: String]
  ) {
    guard !defaults.objectIsForced(forKey: key),
      let value = defaults.string(forKey: key)
    else { return }

    providerConfiguration[key] = value
  }

  private func migrateLegacyBool(_ key: String, into providerConfiguration: inout [String: String])
  {
    guard !defaults.objectIsForced(forKey: key),
      let value = defaults.object(forKey: key) as? Bool
    else { return }

    providerConfiguration[key] = ConfigurationValue.string(value)
  }

  private func handleUserDefaultsChanged() {
    handleConfigurationChanged()
  }

  private func handleConfigurationChanged() {
    self.publishedInternetResourceEnabled = internetResourceEnabled
    self.publishedHideAdminPortalMenuItem = hideAdminPortalMenuItem
    self.publishedHideResourceList = hideResourceList

    objectWillChange.send()
  }
}

// Configuration does not conform to Decodable, so introduce a simpler type here to encode for IPC
public struct TunnelConfiguration: Codable, Sendable {
  public let apiURL: String
  public let accountSlug: String
  public let logFilter: String
  public let internetResourceEnabled: Bool

  public init(apiURL: String, accountSlug: String, logFilter: String, internetResourceEnabled: Bool)
  {
    self.apiURL = apiURL
    self.accountSlug = accountSlug
    self.logFilter = logFilter
    self.internetResourceEnabled = internetResourceEnabled
  }

  public static func fromProviderConfiguration(
    // swiftlint:disable:next discouraged_optional_collection - nil means no provider config exists
    _ providerConfiguration: [String: Any]?
  ) -> TunnelConfiguration? {
    guard let providerConfiguration else { return nil }

    let values = providerConfiguration.stringValues()

    return TunnelConfiguration(
      apiURL: values[Configuration.Keys.apiURL] ?? ConfigurationDefaults.apiURL,
      accountSlug: values[Configuration.Keys.accountSlug] ?? ConfigurationDefaults.accountSlug,
      logFilter: values[Configuration.Keys.logFilter] ?? ConfigurationDefaults.logFilter,
      internetResourceEnabled: ConfigurationValue.bool(
        values[Configuration.Keys.internetResourceEnabled],
        default: ConfigurationDefaults.internetResourceEnabled
      )
    )
  }
}

extension TunnelConfiguration: Equatable {
  public static func == (lhs: TunnelConfiguration, rhs: TunnelConfiguration) -> Bool {
    return lhs.apiURL == rhs.apiURL && lhs.accountSlug == rhs.accountSlug
      && lhs.logFilter == rhs.logFilter
      && lhs.internetResourceEnabled == rhs.internetResourceEnabled
  }
}

extension Dictionary where Key == String, Value == Any {
  fileprivate func stringValues() -> [String: String] {
    reduce(into: [:]) { result, element in
      if let string = element.value as? String {
        result[element.key] = string
      } else if let bool = element.value as? Bool {
        result[element.key] = bool ? "true" : "false"
      }
    }
  }
}
