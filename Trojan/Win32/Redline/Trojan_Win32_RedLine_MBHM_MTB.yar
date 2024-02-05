
rule Trojan_Win32_RedLine_MBHM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBHM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d5 33 c0 33 d2 66 90 01 04 33 c9 66 89 90 01 03 8d 44 24 3c 50 66 89 90 01 03 8b 4c 24 1c 51 90 00 } //01 00 
		$a_01_1 = {6e 75 6d 61 6c 69 68 69 6a 75 77 75 66 61 74 61 72 61 6d 6f 20 76 6f 6c 65 6b 61 78 6f 79 75 66 75 79 6f 6a 6f 74 61 7a 75 77 } //00 00 
	condition:
		any of ($a_*)
 
}