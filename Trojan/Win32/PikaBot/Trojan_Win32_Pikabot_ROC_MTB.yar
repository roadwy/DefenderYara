
rule Trojan_Win32_Pikabot_ROC_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.ROC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 f7 ff 8a 84 15 90 01 04 89 d1 8a 94 1d f4 fe ff ff 88 94 0d f4 fe ff ff 8b 55 08 88 84 1d f4 fe ff ff 02 84 0d f4 fe ff ff 0f b6 c0 8a 84 05 90 01 04 32 04 32 8b 55 18 88 04 32 46 eb 90 00 } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //00 00  DllUnregisterServer
	condition:
		any of ($a_*)
 
}