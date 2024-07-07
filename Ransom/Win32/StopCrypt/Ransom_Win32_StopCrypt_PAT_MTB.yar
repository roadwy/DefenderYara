
rule Ransom_Win32_StopCrypt_PAT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 44 24 04 c2 04 00 81 00 90 01 01 34 ef c6 c3 55 8d 6c 24 90 01 01 81 ec 90 00 } //3
		$a_03_1 = {03 c1 33 c7 83 3d 90 01 04 27 c7 05 90 01 04 2e ce 50 91 90 00 } //1
		$a_03_2 = {03 c1 33 c6 83 3d 90 01 04 27 c7 05 90 01 04 2e ce 50 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}