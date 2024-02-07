
rule Trojan_BAT_AsyncRAT_G_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 00 69 00 6c 00 65 00 3a 00 2f 00 2f 00 2f 00 } //02 00  file:///
		$a_01_1 = {40 00 45 00 43 00 48 00 4f 00 20 00 4f 00 46 00 46 00 } //02 00  @ECHO OFF
		$a_01_2 = {70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 3e 00 20 00 6e 00 75 00 6c 00 } //02 00  ping 127.0.0.1 > nul
		$a_01_3 = {65 00 63 00 68 00 6f 00 20 00 6a 00 20 00 7c 00 20 00 64 00 65 00 6c 00 20 00 2f 00 46 00 } //01 00  echo j | del /F
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //01 00  VirtualProtect
		$a_01_5 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  CheckRemoteDebuggerPresent
	condition:
		any of ($a_*)
 
}