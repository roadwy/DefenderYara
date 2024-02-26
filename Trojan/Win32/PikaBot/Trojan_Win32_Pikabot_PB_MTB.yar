
rule Trojan_Win32_Pikabot_PB_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_1 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllUnregisterServer
		$a_03_2 = {f7 f6 0f b6 54 15 90 01 01 33 ca 8b 45 90 01 01 03 45 90 01 01 88 08 eb 90 01 01 8b 4d 90 01 01 51 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}