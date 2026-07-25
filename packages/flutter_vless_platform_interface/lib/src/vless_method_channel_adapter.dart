import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

import 'vless_platform.dart';
import 'vless_status.dart';

class VlessMethodChannelAdapter extends VlessPlatform {
  VlessMethodChannelAdapter({
    this.methodChannel = const MethodChannel('flutter_vless'),
    this.eventChannel = const EventChannel('flutter_vless/status'),
  });

  @visibleForTesting
  final MethodChannel methodChannel;

  @visibleForTesting
  final EventChannel eventChannel;

  StreamSubscription<dynamic>? _statusSubscription;

  @override
  Future<void> initializeVless({
    required void Function(VlessStatus status) onStatusChanged,
    required String notificationIconResourceType,
    required String notificationIconResourceName,
    required String providerBundleIdentifier,
    required String groupIdentifier,
  }) async {
    await _statusSubscription?.cancel();
    _statusSubscription = eventChannel
        .receiveBroadcastStream()
        .distinct()
        .listen((Object? event) {
      final status = VlessStatus.tryParse(event);
      if (status != null) {
        onStatusChanged(status);
      } else {
        debugPrint('Ignoring malformed VLESS status payload: $event');
      }
    }, onError: (Object error, StackTrace stackTrace) {
      debugPrint('VLESS status stream error: $error');
    });

    await methodChannel.invokeMethod(
      'initializeVless',
      {
        'notificationIconResourceType': notificationIconResourceType,
        'notificationIconResourceName': notificationIconResourceName,
        'providerBundleIdentifier': providerBundleIdentifier,
        'groupIdentifier': groupIdentifier,
      },
    );
  }

  @override
  Future<void> startVless({
    required String remark,
    required String config,
    required String notificationDisconnectButtonName,
    List<String>? blockedApps,
    List<String>? allowedApps,
    List<String>? bypassSubnets,
    bool proxyOnly = false,
    bool perAppProxy = false,
    bool applySystemProxy = true,
  }) async {
    await methodChannel.invokeMethod('startVless', {
      'remark': remark,
      'config': config,
      'blocked_apps': blockedApps,
      'allowed_apps': allowedApps,
      'bypass_subnets': bypassSubnets,
      'proxy_only': proxyOnly,
      'per_app_proxy': perAppProxy,
      'apply_system_proxy': applySystemProxy,
      'notificationDisconnectButtonName': notificationDisconnectButtonName,
    });
  }

  @override
  Future<void> stopVless() async {
    await methodChannel.invokeMethod('stopVless');
  }

  @override
  Future<int> getServerDelay({
    required String config,
    required String url,
  }) async {
    return await methodChannel.invokeMethod('getServerDelay', {
      'config': config,
      'url': url,
    });
  }

  @override
  Future<int> getConnectedServerDelay(String url) async {
    return await methodChannel.invokeMethod(
      'getConnectedServerDelay',
      {'url': url},
    );
  }

  @override
  Future<bool> requestPermission() async {
    return (await methodChannel.invokeMethod('requestPermission')) ?? false;
  }

  @override
  Future<String> getCoreVersion() async {
    return await methodChannel.invokeMethod('getCoreVersion');
  }

  @override
  Future<String> getProviderDebugSnapshot() async {
    return await methodChannel.invokeMethod('getProviderDebugSnapshot') ?? '';
  }

  @override
  Future<String> getProviderDebugLogFile() async {
    return await methodChannel.invokeMethod('getProviderDebugLogFile') ?? '';
  }

  @override
  Future<String> getProviderExternalIp() async {
    return await methodChannel.invokeMethod('getProviderExternalIp') ?? '';
  }
}
