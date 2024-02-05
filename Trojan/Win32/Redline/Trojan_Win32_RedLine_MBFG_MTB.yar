
rule Trojan_Win32_RedLine_MBFG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {33 c1 2b f0 89 44 24 14 8b c6 c1 e0 04 89 44 24 10 8b 44 24 28 01 44 24 10 } //01 00 
		$a_01_1 = {66 6f 64 61 6a 69 7a 69 74 69 66 75 76 75 68 61 63 69 6c 75 76 65 73 69 67 69 7a 6f 6d 6f 20 6d 69 77 75 64 6f 78 69 70 65 64 6f 67 61 70 6f } //00 00 
	condition:
		any of ($a_*)
 
}