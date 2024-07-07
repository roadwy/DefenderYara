
rule Ransom_Win64_Nokoyawa_AA{
	meta:
		description = "Ransom:Win64/Nokoyawa.AA,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 1f 00 07 00 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //1
		$a_01_1 = {3d 7c c4 8c 7c } //5
		$a_01_2 = {3d 89 28 f0 d6 } //5
		$a_01_3 = {3d 15 b7 7b c2 } //5
		$a_01_4 = {3d 26 b4 80 7c } //5
		$a_01_5 = {3d b5 99 f2 11 } //5
		$a_01_6 = {3d 95 39 fb 78 } //5
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=31
 
}