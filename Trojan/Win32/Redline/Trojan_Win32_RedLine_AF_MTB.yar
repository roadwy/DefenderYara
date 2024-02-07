
rule Trojan_Win32_RedLine_AF_MTB{
	meta:
		description = "Trojan:Win32/RedLine.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 10 8b 55 08 03 55 fc 0f b6 02 33 c1 8b 4d 08 03 4d fc 88 01 eb } //01 00 
		$a_01_1 = {57 6b 75 78 7a 67 73 58 7b 74 7b 6a 67 75 } //00 00  WkuxzgsX{t{jgu
	condition:
		any of ($a_*)
 
}