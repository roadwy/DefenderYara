
rule Trojan_Win32_Emotet_ADB_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ADB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c0 83 c4 90 01 01 ab 33 d2 6a 90 01 01 ab 59 68 90 01 04 68 90 01 04 ab 90 00 } //01 00 
		$a_03_1 = {6b 45 fc 14 68 90 01 04 51 89 45 fc 6b 45 fc 90 01 01 89 45 fc 8b 45 fc f7 f1 89 45 fc 81 75 fc 90 01 04 8b 45 fc 8b 45 f4 8b 45 f8 e8 90 01 04 83 c4 90 01 01 53 ff 75 90 01 01 56 ff d0 5f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}