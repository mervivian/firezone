//
//  ConfigurationTests.swift
//  (c) 2026 Firezone, Inc.
//  LICENSE: Apache-2.0
//

import Combine
import Foundation
import Testing

@testable import FirezoneKit

private final class ForcedUserDefaults: UserDefaults {
  private let forcedKeys: Set<String>

  init?(forcedKeys: Set<String>) {
    self.forcedKeys = forcedKeys

    super.init(suiteName: "dev.firezone.firezone.tests.\(UUID().uuidString)")
  }

  override func objectIsForced(forKey defaultName: String) -> Bool {
    forcedKeys.contains(defaultName)
  }
}

@Suite("Configuration Tests")
struct ConfigurationTests {

  // MARK: - Default Values

  @Test("Returns default values when provider configuration is empty")
  @MainActor
  func defaultValues() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    #expect(config.authURL == ConfigurationDefaults.authURL)
    #expect(config.apiURL == ConfigurationDefaults.apiURL)
    #expect(config.logFilter == ConfigurationDefaults.logFilter)
    #expect(config.accountSlug == ConfigurationDefaults.accountSlug)
    #expect(config.actorName == ConfigurationDefaults.actorName)
    #expect(config.supportURL == ConfigurationDefaults.supportURL)
    #expect(config.connectOnStart == ConfigurationDefaults.connectOnStart)
    #expect(config.startOnLogin == ConfigurationDefaults.startOnLogin)
    #expect(config.disableUpdateCheck == ConfigurationDefaults.disableUpdateCheck)
    #expect(config.internetResourceEnabled == false)
    #expect(config.hideAdminPortalMenuItem == false)
    #expect(config.hideResourceList == false)
  }

  @Test("String defaults use fallback when key is missing")
  @MainActor
  func stringDefaultsFallback() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    // Verify the fallback logic works - string(forKey:) returns nil, so ?? kicks in
    // These assertions verify the actual values, not just self-comparison
    #expect(config.authURL.starts(with: "https://app.fire"))
    #expect(config.apiURL.starts(with: "wss://api.fire"))
    #expect(config.supportURL == "https://www.firezone.dev/support")
    #expect(config.accountSlug.isEmpty)

    // Confirm nothing was written to UserDefaults (defaults are computed, not stored)
    #expect(defaults.string(forKey: "authURL") == nil)
    #expect(defaults.string(forKey: "apiURL") == nil)
    #expect(defaults.string(forKey: "supportURL") == nil)
  }

  // MARK: - Read/Write Properties

  @Test("String properties persist to provider configuration")
  @MainActor
  func stringPropertiesPersist() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    config.authURL = "https://custom.auth.url"
    config.apiURL = "wss://custom.api.url"
    config.logFilter = "trace"
    config.accountSlug = "test-slug"
    config.actorName = "Test User"

    #expect(config.authURL == "https://custom.auth.url")
    #expect(config.apiURL == "wss://custom.api.url")
    #expect(config.logFilter == "trace")
    #expect(config.accountSlug == "test-slug")
    #expect(config.actorName == "Test User")
    #expect(config.supportURL == ConfigurationDefaults.supportURL)

    let providerConfiguration = config.toProviderConfiguration()

    // User-editable connection settings are no longer written to UserDefaults.
    #expect(defaults.string(forKey: "authURL") == nil)
    #expect(defaults.string(forKey: "apiURL") == nil)
    #expect(defaults.string(forKey: "logFilter") == nil)
    #expect(defaults.string(forKey: "accountSlug") == nil)
    #expect(defaults.string(forKey: "actorName") == nil)
    #expect(providerConfiguration["authURL"] == "https://custom.auth.url")
    #expect(providerConfiguration["apiURL"] == "wss://custom.api.url")
    #expect(providerConfiguration["logFilter"] == "trace")
    #expect(providerConfiguration["accountSlug"] == "test-slug")
    #expect(providerConfiguration["actorName"] == "Test User")

    #expect(defaults.string(forKey: "supportURL") == nil)
  }

  @Test("Boolean properties persist to their configured stores")
  @MainActor
  func booleanPropertiesPersist() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    config.connectOnStart = true
    config.startOnLogin = true
    config.internetResourceEnabled = true

    #expect(config.connectOnStart == true)
    #expect(config.startOnLogin == true)
    #expect(config.disableUpdateCheck == false)
    #expect(config.internetResourceEnabled == true)
    #expect(config.hideAdminPortalMenuItem == false)
    #expect(config.hideResourceList == false)

    let providerConfiguration = config.toProviderConfiguration()

    #expect(defaults.object(forKey: "connectOnStart") == nil)
    #expect(defaults.object(forKey: "startOnLogin") == nil)
    #expect(defaults.object(forKey: "internetResourceEnabled") == nil)
    #expect(providerConfiguration["connectOnStart"] == "true")
    #expect(providerConfiguration["startOnLogin"] == "true")
    #expect(providerConfiguration["internetResourceEnabled"] == "true")

    #expect(defaults.object(forKey: "disableUpdateCheck") == nil)
    #expect(defaults.object(forKey: "hideAdminPortalMenuItem") == nil)
    #expect(defaults.object(forKey: "hideResourceList") == nil)
  }

  @Test("MDM-only UserDefaults values are ignored when unforced")
  @MainActor
  func mdmOnlyValuesIgnoreUnforcedUserDefaults() async {
    let defaults = UserDefaults.makeTestDefaults()

    defaults.set(true, forKey: "hideAdminPortalMenuItem")
    defaults.set(true, forKey: "hideResourceList")
    defaults.set(true, forKey: "disableUpdateCheck")
    defaults.set("https://custom.support.url", forKey: "supportURL")

    let config = Configuration(userDefaults: defaults)

    #expect(config.hideAdminPortalMenuItem == false)
    #expect(config.hideResourceList == false)
    #expect(config.disableUpdateCheck == ConfigurationDefaults.disableUpdateCheck)
    #expect(config.supportURL == ConfigurationDefaults.supportURL)
  }

  @Test("Forced MDM values override effective configuration without changing provider storage")
  @MainActor
  func forcedValuesOverrideEffectiveConfigurationOnly() async throws {
    let defaults = try #require(
      ForcedUserDefaults(forcedKeys: [
        Configuration.Keys.apiURL,
        Configuration.Keys.internetResourceEnabled,
      ])
    )
    defaults.set("wss://mdm.api", forKey: Configuration.Keys.apiURL)
    defaults.set(true, forKey: Configuration.Keys.internetResourceEnabled)

    let config = Configuration(userDefaults: defaults)
    config.loadProviderConfiguration(
      [
        Configuration.Keys.apiURL: "wss://provider.api",
        Configuration.Keys.internetResourceEnabled: "false",
      ],
      migrateUserDefaults: false
    )

    #expect(config.apiURL == "wss://mdm.api")
    #expect(config.internetResourceEnabled == true)
    #expect(config.toTunnelConfiguration().apiURL == "wss://mdm.api")
    #expect(config.toTunnelConfiguration().internetResourceEnabled == true)

    let providerConfiguration = config.toProviderConfiguration()
    #expect(providerConfiguration[Configuration.Keys.apiURL] == "wss://provider.api")
    #expect(providerConfiguration[Configuration.Keys.internetResourceEnabled] == "false")
  }

  @Test("Settings save skips forced MDM fields")
  @MainActor
  func settingsSaveSkipsForcedFields() async throws {
    let defaults = try #require(
      ForcedUserDefaults(forcedKeys: [
        Configuration.Keys.authURL
      ])
    )
    defaults.set("https://mdm.auth", forKey: Configuration.Keys.authURL)

    let config = Configuration(userDefaults: defaults)
    config.loadProviderConfiguration(
      [
        Configuration.Keys.authURL: "https://provider.auth",
        Configuration.Keys.apiURL: "wss://provider.api",
      ],
      migrateUserDefaults: false
    )

    let viewModel = SettingsViewModel(configuration: config)
    viewModel.authURL = "https://attempted-user-change.auth"
    viewModel.apiURL = "wss://saved-user-change.api"

    try await viewModel.save()

    let providerConfiguration = config.toProviderConfiguration()
    #expect(providerConfiguration[Configuration.Keys.authURL] == "https://provider.auth")
    #expect(providerConfiguration[Configuration.Keys.apiURL] == "wss://saved-user-change.api")
  }

  // MARK: - TunnelConfiguration

  @Test("toTunnelConfiguration returns correct values")
  @MainActor
  func tunnelConfiguration() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    config.apiURL = "wss://test.api"
    config.accountSlug = "test-account"
    config.logFilter = "warn"
    config.internetResourceEnabled = true

    let tunnelConfig = config.toTunnelConfiguration()

    #expect(tunnelConfig.apiURL == "wss://test.api")
    #expect(tunnelConfig.accountSlug == "test-account")
    #expect(tunnelConfig.logFilter == "warn")
    #expect(tunnelConfig.internetResourceEnabled == true)
  }

  @Test("TunnelConfiguration equality")
  func tunnelConfigurationEquality() {
    let config1 = TunnelConfiguration(
      apiURL: "wss://api",
      accountSlug: "slug",
      logFilter: "info",
      internetResourceEnabled: true
    )

    let config2 = TunnelConfiguration(
      apiURL: "wss://api",
      accountSlug: "slug",
      logFilter: "info",
      internetResourceEnabled: true
    )

    let config3 = TunnelConfiguration(
      apiURL: "wss://different",
      accountSlug: "slug",
      logFilter: "info",
      internetResourceEnabled: true
    )

    #expect(config1 == config2)
    #expect(config1 != config3)
  }

  // MARK: - Published Properties Initialization

  @Test("Published properties ignore unforced UserDefaults")
  @MainActor
  func publishedPropertiesInitialized() async {
    let defaults = UserDefaults.makeTestDefaults()

    // Unforced MDM-only keys should not affect Configuration.
    defaults.set(true, forKey: "hideAdminPortalMenuItem")
    defaults.set(true, forKey: "hideResourceList")

    let config = Configuration(userDefaults: defaults)
    config.loadProviderConfiguration(
      ["internetResourceEnabled": "true"],
      migrateUserDefaults: false
    )

    #expect(config.publishedInternetResourceEnabled == true)
    #expect(config.publishedHideAdminPortalMenuItem == false)
    #expect(config.publishedHideResourceList == false)
  }

  // MARK: - Reactive Published Property Updates

  @Test("Published properties update when regular properties change")
  @MainActor
  func publishedPropertiesUpdateReactively() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    // Initially false
    #expect(config.publishedInternetResourceEnabled == false)

    // Wait for the published property to update to the expected value
    await confirmation { confirm in
      let cancellable = config.$publishedInternetResourceEnabled
        .sink { value in
          if value { confirm() }  // only confirm when true
        }

      config.internetResourceEnabled = true

      // Give async notification time to propagate
      try? await Task.sleep(for: .milliseconds(100))

      _ = cancellable
    }
  }

  @Test("Published MDM-only properties ignore unforced UserDefaults changes")
  @MainActor
  func publishedPropertiesUpdateFromExternalChanges() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    #expect(config.publishedHideResourceList == false)

    defaults.set(true, forKey: "hideResourceList")

    // Give async notification time to propagate
    try? await Task.sleep(for: .milliseconds(100))

    #expect(config.publishedHideResourceList == false)
  }

  @Test("objectWillChange emits when properties change")
  @MainActor
  func objectWillChangeEmits() async {
    let defaults = UserDefaults.makeTestDefaults()
    let config = Configuration(userDefaults: defaults)

    // Wait for objectWillChange to emit and verify state changed correctly
    var confirmed = false
    await confirmation { confirm in
      let cancellable = config.objectWillChange.sink { [weak config] _ in
        // Verify the state is correct when objectWillChange fires (only confirm once)
        if !confirmed && config?.publishedInternetResourceEnabled == true {
          confirmed = true
          confirm()
        }
      }

      config.internetResourceEnabled = true

      // Give async notification time to propagate
      try? await Task.sleep(for: .milliseconds(100))

      _ = cancellable
    }
  }

  // MARK: - Reading Pre-existing Values

  @Test("Configuration migrates pre-existing UserDefaults values")
  @MainActor
  func readsPreExistingValues() async {
    let defaults = UserDefaults.makeTestDefaults()

    // Set values before creating Configuration
    defaults.set("https://preset.auth", forKey: "authURL")
    defaults.set("wss://preset.api", forKey: "apiURL")
    defaults.set("Preset User", forKey: "actorName")
    defaults.set(true, forKey: "connectOnStart")
    defaults.set(true, forKey: "internetResourceEnabled")

    let config = Configuration(userDefaults: defaults)
    config.loadProviderConfiguration([:], migrateUserDefaults: true)

    #expect(config.authURL == "https://preset.auth")
    #expect(config.apiURL == "wss://preset.api")
    #expect(config.actorName == "Preset User")
    #expect(config.connectOnStart == true)
    #expect(config.internetResourceEnabled == true)

    // Published properties should also reflect pre-existing values
    #expect(config.publishedInternetResourceEnabled == true)
  }

  // MARK: - Multiple Configuration Instances

  @Test("Provider configuration round trips between Configuration instances")
  @MainActor
  func providerConfigurationRoundTrip() async throws {
    let defaults = UserDefaults.makeTestDefaults()
    let config1 = Configuration(userDefaults: defaults)
    let config2 = Configuration(userDefaults: defaults)

    config1.authURL = "https://shared.url"
    config1.apiURL = "wss://shared.api"
    config1.actorName = "Shared User"
    config1.internetResourceEnabled = true
    let providerConfiguration = config1.toProviderConfiguration()

    config2.loadProviderConfiguration(providerConfiguration, migrateUserDefaults: false)

    #expect(config2.authURL == "https://shared.url")
    #expect(config2.apiURL == "wss://shared.api")
    #expect(config2.actorName == "Shared User")
    #expect(config2.internetResourceEnabled == true)
  }
}

// MARK: - TunnelConfiguration Codable Tests

@Suite("TunnelConfiguration Codable Tests")
struct TunnelConfigurationCodableTests {

  @Test("TunnelConfiguration encodes and decodes correctly")
  func encodeDecode() throws {
    let original = TunnelConfiguration(
      apiURL: "wss://api.example.com",
      accountSlug: "my-account",
      logFilter: "debug",
      internetResourceEnabled: true
    )

    let encoder = JSONEncoder()
    let data = try encoder.encode(original)

    let decoder = JSONDecoder()
    let decoded = try decoder.decode(TunnelConfiguration.self, from: data)

    #expect(decoded == original)
  }

  @Test("TunnelConfiguration decodes from JSON string")
  func decodeFromJSON() throws {
    let json = """
      {
        "apiURL": "wss://test.api",
        "accountSlug": "test-slug",
        "logFilter": "info",
        "internetResourceEnabled": false
      }
      """

    let jsonData = try #require(json.data(using: .utf8))
    let decoder = JSONDecoder()
    let config = try decoder.decode(TunnelConfiguration.self, from: jsonData)

    #expect(config.apiURL == "wss://test.api")
    #expect(config.accountSlug == "test-slug")
    #expect(config.logFilter == "info")
    #expect(config.internetResourceEnabled == false)
  }

  @Test("TunnelConfiguration builds from provider configuration")
  func fromProviderConfiguration() throws {
    let config = try #require(
      TunnelConfiguration.fromProviderConfiguration([
        "apiURL": "wss://provider.api",
        "accountSlug": "provider-slug",
        "logFilter": "debug",
        "internetResourceEnabled": "true",
      ])
    )

    #expect(config.apiURL == "wss://provider.api")
    #expect(config.accountSlug == "provider-slug")
    #expect(config.logFilter == "debug")
    #expect(config.internetResourceEnabled == true)
  }

}

// MARK: - ProviderMessage Codable Tests

@Suite("ProviderMessage Codable Tests")
struct ProviderMessageCodableTests {
  private let encoder = JSONEncoder()
  private let decoder = JSONDecoder()

  private func roundTrip(_ message: ProviderMessage) throws -> ProviderMessage {
    let data = try encoder.encode(message)
    return try decoder.decode(ProviderMessage.self, from: data)
  }

  @Test("getEncodedFirezoneId round-trips through JSON")
  func getEncodedFirezoneIdRoundTrip() throws {
    let decoded = try roundTrip(.getEncodedFirezoneId)

    if case .getEncodedFirezoneId = decoded {
      // success
    } else {
      Issue.record("Expected .getEncodedFirezoneId, got \(decoded)")
    }
  }

  @Test("All valueless cases round-trip through JSON")
  func valuelessCasesRoundTrip() throws {
    let cases: [ProviderMessage] = [
      .signOut, .clearLogs, .getLogFolderSize, .exportLogs, .getEncodedFirezoneId,
    ]

    for message in cases {
      let decoded = try roundTrip(message)
      let originalData = try encoder.encode(message)
      let decodedData = try encoder.encode(decoded)
      #expect(originalData == decodedData, "Round-trip failed for \(message)")
    }
  }

  @Test("getState round-trips through JSON")
  func getStateRoundTrip() throws {
    let hash = Data([0x01, 0x02, 0x03])
    let decoded = try roundTrip(.getState(hash))

    if case .getState(let decodedHash) = decoded {
      #expect(decodedHash == hash)
    } else {
      Issue.record("Expected .getState, got \(decoded)")
    }
  }

  @Test("setConfiguration round-trips through JSON")
  func setConfigurationRoundTrip() throws {
    let config = TunnelConfiguration(
      apiURL: "wss://api.example.com",
      accountSlug: "test",
      logFilter: "info",
      internetResourceEnabled: true
    )
    let decoded = try roundTrip(.setConfiguration(config))

    if case .setConfiguration(let decodedConfig) = decoded {
      #expect(decodedConfig == config)
    } else {
      Issue.record("Expected .setConfiguration, got \(decoded)")
    }
  }
}
