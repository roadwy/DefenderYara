
rule Ransom_Win32_StopCrypt_PAQ_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {81 00 03 35 ef c6 c3 55 8b ec } //4
		$a_03_1 = {03 c1 33 c7 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 } //1
		$a_03_2 = {03 c1 33 c6 83 3d ?? ?? ?? ?? 27 c7 05 ?? ?? ?? ?? 2e ce 50 91 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=5
 
}