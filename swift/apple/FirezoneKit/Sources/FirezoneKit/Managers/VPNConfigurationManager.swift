//
//  VPNConfigurationManager.swift
//
//
//  Created by Jamil Bou Kheir on 4/2/24.
//
//  Abstracts the nitty gritty of loading and saving to our
//  VPN configuration in system preferences.

import Foundation
import NetworkExtension

// MARK: - Protocols

@MainActor
public protocol TunnelProviderManager: AnyObject {
  var isEnabled: Bool { get set }
  var localizedDescription: String? { get set }
  var protocolConfiguration: NEVPNProtocol? { get set }
  var connection: NEVPNConnection { get }

  func saveToPreferences() async throws
  func loadFromPreferences() async throws
}

@MainActor
public protocol TunnelProviderManagerFactory {
  func loadAllFromPreferences() async throws -> [any TunnelProviderManager]
  func createManager() -> any TunnelProviderManager
}

// MARK: - NetworkExtension Conformances

extension NETunnelProviderManager: TunnelProviderManager {}

@MainActor
public final class NETunnelProviderManagerFactory: TunnelProviderManagerFactory {
  public init() {}

  public func loadAllFromPreferences() async throws -> [any TunnelProviderManager] {
    try await NETunnelProviderManager.loadAllFromPreferences()
  }

  public func createManager() -> any TunnelProviderManager {
    NETunnelProviderManager()
  }
}

// MARK: - VPNConfigurationManager

enum VPNConfigurationManagerError: Error {
  case managerNotInitialized
  case savedProtocolConfigurationIsInvalid

  var localizedDescription: String {
    switch self {
    case .managerNotInitialized:
      return "NETunnelProviderManager is not yet initialized. Race condition?"
    case .savedProtocolConfigurationIsInvalid:
      return "Saved protocol configuration is invalid. Check types?"
    }
  }
}

// NEVPNManager callbacks are documented to arrive on main thread;
// we isolate to @MainActor to align with this design.
@MainActor
public final class VPNConfigurationManager {
  let manager: any TunnelProviderManager

  // App cannot run without bundle identifier - force unwrap is safe
  // swiftlint:disable:next force_unwrapping
  public static let bundleIdentifier: String = "\(Bundle.main.bundleIdentifier!).network-extension"
  static let bundleDescription = "Firezone"

  // Initialize and save a new VPN configuration in system Preferences
  init(manager: any TunnelProviderManager) async throws {
    let protocolConfiguration = NETunnelProviderProtocol()

    protocolConfiguration.providerConfiguration = Configuration.defaultProviderConfiguration(
      markUserDefaultsMigrated: false
    )
    protocolConfiguration.providerBundleIdentifier = VPNConfigurationManager.bundleIdentifier
    protocolConfiguration.serverAddress = "Firezone"  // can be any non-empty string
    manager.localizedDescription = VPNConfigurationManager.bundleDescription
    manager.protocolConfiguration = protocolConfiguration

    try await manager.saveToPreferences()
    try await manager.loadFromPreferences()

    self.manager = manager
  }

  init(from manager: any TunnelProviderManager) {
    self.manager = manager
  }

  static func providerConfiguration(
    protocolConfiguration: NETunnelProviderProtocol?
  )
    // swiftlint:disable:next discouraged_optional_collection - nil means no provider config exists
    -> [String: String]?
  {
    guard let protocolConfiguration = protocolConfiguration,
      let providerConfiguration = protocolConfiguration.providerConfiguration as? [String: String]
    else {
      return nil
    }

    return providerConfiguration
  }

  static func load(using factory: TunnelProviderManagerFactory) async throws
    -> VPNConfigurationManager?
  {
    // loadAllFromPreferences() returns list of VPN configurations created by our main app's bundle ID.
    // Since our bundle ID can change (by us), find the one that's current and ignore the others.
    let managers = try await factory.loadAllFromPreferences()

    for manager in managers where manager.localizedDescription == bundleDescription {
      return VPNConfigurationManager(from: manager)
    }

    return nil
  }

  // If another VPN is activated on the system, ours becomes disabled. This is provided so that we may call it before
  // each start attempt in order to reactivate our configuration.
  func enable() async throws {
    manager.isEnabled = true
    try await manager.saveToPreferences()
    try await manager.loadFromPreferences()
  }

  func session() -> NETunnelProviderSession? {
    return manager.connection as? NETunnelProviderSession
  }

  func loadConfiguration(into configuration: Configuration, userDefaults: UserDefaults) async throws
  {
    guard let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol
    else {
      throw VPNConfigurationManagerError.savedProtocolConfigurationIsInvalid
    }

    let providerConfiguration =
      Self.providerConfiguration(
        protocolConfiguration: protocolConfiguration
      ) ?? [:]

    let shouldMigrateUserDefaults =
      providerConfiguration[Configuration.Keys.userDefaultsMigrated] != "true"

    configuration.loadProviderConfiguration(
      providerConfiguration,
      migrateUserDefaults: shouldMigrateUserDefaults
    )

    try await save(configuration: configuration)
  }

  func save(
    configuration: Configuration,
    markUserDefaultsMigrated: Bool = true
  ) async throws {
    guard let protocolConfiguration = manager.protocolConfiguration as? NETunnelProviderProtocol
    else {
      throw VPNConfigurationManagerError.savedProtocolConfigurationIsInvalid
    }

    let providerConfiguration =
      Self.providerConfiguration(protocolConfiguration: protocolConfiguration) ?? [:]
    let newProviderConfiguration = configuration.toProviderConfiguration(
      markUserDefaultsMigrated: markUserDefaultsMigrated
    )

    if providerConfiguration == newProviderConfiguration
      && protocolConfiguration.serverAddress == "Firezone"
    {
      return
    }

    protocolConfiguration.providerConfiguration = newProviderConfiguration
    protocolConfiguration.serverAddress = "Firezone"
    manager.protocolConfiguration = protocolConfiguration

    try await manager.saveToPreferences()
    try await manager.loadFromPreferences()
  }
}
