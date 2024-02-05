
rule Trojan_Win32_Azorult_DSK_MTB{
	meta:
		description = "Trojan:Win32/Azorult.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_02_0 = {c7 45 fc 43 94 0e 00 81 45 fc 7e 0a 18 00 69 0d 90 01 04 fd 43 03 00 8b 45 fc 83 c0 02 03 c1 a3 90 00 } //02 00 
		$a_02_1 = {8b 44 24 10 8b 54 24 14 33 c6 c7 05 90 01 04 ca e3 40 df 8b 74 24 28 81 c2 47 86 c8 61 2b d8 89 54 24 14 83 ef 01 0f 85 90 00 } //02 00 
		$a_02_2 = {8a 8c 3e f5 d0 00 00 8b 15 90 01 04 88 0c 32 8b 4d fc 5f 33 cd 5e e8 90 01 04 8b e5 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}