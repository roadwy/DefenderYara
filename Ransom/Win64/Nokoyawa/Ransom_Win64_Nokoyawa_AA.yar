
rule Ransom_Win64_Nokoyawa_AA{
	meta:
		description = "Ransom:Win64/Nokoyawa.AA,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //05 00 
		$a_01_1 = {3d 7c c4 8c 7c } //05 00 
		$a_01_2 = {3d 89 28 f0 d6 } //05 00 
		$a_01_3 = {3d 15 b7 7b c2 } //05 00 
		$a_01_4 = {3d 26 b4 80 7c } //05 00 
		$a_01_5 = {3d b5 99 f2 11 } //05 00 
		$a_01_6 = {3d 95 39 fb 78 } //00 00 
		$a_00_7 = {5d 04 00 00 f2 1c 05 80 5c 22 00 00 f3 1c 05 80 00 00 01 00 04 00 0c 00 88 21 4c 6e 6b 67 } //65 74 
	condition:
		any of ($a_*)
 
}