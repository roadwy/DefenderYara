
rule Ransom_Win32_StopCrypt_PS_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {c1 e0 04 89 01 c3 } //1
		$a_03_1 = {c2 08 00 33 44 24 04 c2 04 00 81 00 ?? 36 ef c6 c3 01 08 c3 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}