
rule Ransom_Win32_StopCrypt_PAT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 44 24 04 c2 04 00 81 00 ?? 34 ef c6 c3 55 8d 6c 24 ?? 81 ec } //3
		$a_03_1 = {03 c1 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 } //1
		$a_03_2 = {03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 } //1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=4
 
}