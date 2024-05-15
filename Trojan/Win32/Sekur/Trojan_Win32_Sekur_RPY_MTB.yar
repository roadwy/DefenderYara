
rule Trojan_Win32_Sekur_RPY_MTB{
	meta:
		description = "Trojan:Win32/Sekur.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 43 28 83 7b 30 00 8b 4d 0c 8b 45 08 74 57 8b 7b 38 2b 7b 34 89 7c 24 04 c7 44 24 0c 40 00 00 00 c7 44 24 08 00 30 00 00 c7 04 24 00 00 00 00 ff 53 14 83 ec 10 89 c6 8b 43 34 89 7c 24 08 89 44 24 04 89 34 24 } //00 00 
	condition:
		any of ($a_*)
 
}