
rule Ransom_Win64_ThreeAM_B{
	meta:
		description = "Ransom:Win64/ThreeAM.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 89 f1 48 3d 01 00 50 00 0f 83 } //1
		$a_01_1 = {48 89 f1 b2 31 66 41 b8 30 31 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}