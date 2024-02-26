
rule Trojan_Win32_BatLoader_RPY_MTB{
	meta:
		description = "Trojan:Win32/BatLoader.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 54 24 0c 8b 4c 24 04 8b c2 4a 85 c0 74 17 8b 44 24 08 56 2b c1 8d 72 01 8a 11 80 f2 01 88 14 08 41 4e 75 f4 5e c3 } //00 00 
	condition:
		any of ($a_*)
 
}