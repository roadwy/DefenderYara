
rule Ransom_Win32_StopCrypt_PBJ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 04 00 81 00 e1 34 ef c6 c3 55 8b ec } //1
		$a_03_1 = {03 c7 33 45 90 01 01 33 c1 81 3d 90 01 04 a3 01 00 00 89 45 90 01 01 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}