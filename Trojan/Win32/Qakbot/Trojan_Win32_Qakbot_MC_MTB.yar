
rule Trojan_Win32_Qakbot_MC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d 90 01 04 6a 00 e8 90 01 04 03 d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 2b d8 6a 00 e8 90 01 04 2b d8 a1 90 01 04 33 18 89 1d 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 8b 45 f8 83 c0 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Qakbot_MC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 6a 61 75 7a 79 4f } //01 00  OjauzyO
		$a_01_1 = {57 44 67 76 51 49 39 34 37 50 4e 37 } //01 00  WDgvQI947PN7
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {44 6c 6c 49 6e 73 74 61 6c 6c } //01 00  DllInstall
		$a_01_4 = {6e 64 75 6b 74 70 65 37 30 39 62 66 35 35 2e 64 6c 6c } //00 00  nduktpe709bf55.dll
	condition:
		any of ($a_*)
 
}