
rule Trojan_Win32_RedLineStealer_MD_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 45 fc b8 d6 38 00 00 01 45 fc 8b 45 08 8b 4d fc 8a 0c 01 8b 15 90 01 04 88 0c 02 c9 c2 90 00 } //01 00 
		$a_01_1 = {47 65 74 4d 61 69 6c 73 6c 6f 74 49 6e 66 6f } //01 00 
		$a_01_2 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 45 78 41 } //01 00 
		$a_01_3 = {55 6e 6c 6f 63 6b 46 69 6c 65 45 78 } //00 00 
	condition:
		any of ($a_*)
 
}