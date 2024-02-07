
rule Trojan_Win32_Emotet_MC_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 83 c0 01 89 45 fc 8b 4d fc 3b 4d 10 73 90 01 01 8b 55 08 03 55 fc 0f b6 0a 8b 45 fc 33 d2 f7 75 18 8b 45 14 0f b6 14 10 33 ca 8b 45 0c 03 45 fc 88 08 eb 90 00 } //01 00 
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_2 = {44 6c 6c 55 6e 72 65 67 69 73 74 65 72 53 65 72 76 65 72 4d 6f 64 65 } //00 00  DllUnregisterServerMode
	condition:
		any of ($a_*)
 
}