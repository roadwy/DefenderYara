
rule Ransom_Win32_StopCrypt_PW_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c2 04 00 81 00 a4 36 ef c6 c3 29 08 c3 55 8b ec 81 ec 48 } //1
		$a_03_1 = {c1 e8 05 03 45 90 01 01 03 fa 33 cf 33 c8 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}