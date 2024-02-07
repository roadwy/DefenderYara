
rule Trojan_Win32_Upatre_MG_MTB{
	meta:
		description = "Trojan:Win32/Upatre.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {89 4d c0 ba e5 3c ad d8 89 55 b4 b8 fa 55 1f 62 89 45 a8 b9 90 01 04 8b d1 81 f2 dc c3 8f d7 89 95 74 ff ff ff 8b c1 35 ee b0 ab c7 89 45 e4 89 2d 90 00 } //01 00 
		$a_03_1 = {53 53 50 50 50 50 68 00 00 ef 00 68 90 01 04 68 90 01 04 68 00 02 00 00 e8 90 00 } //01 00 
		$a_01_2 = {58 00 6f 00 76 00 65 00 66 00 78 00 75 00 } //01 00  Xovefxu
		$a_01_3 = {2f 00 69 00 6d 00 61 00 67 00 65 00 73 00 2f 00 6e 00 65 00 77 00 2f 00 54 00 41 00 52 00 47 00 54 00 73 00 70 00 2e 00 65 00 78 00 65 00 } //00 00  /images/new/TARGTsp.exe
	condition:
		any of ($a_*)
 
}