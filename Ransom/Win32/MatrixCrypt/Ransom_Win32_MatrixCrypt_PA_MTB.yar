
rule Ransom_Win32_MatrixCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/MatrixCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {69 c9 fd 43 03 00 81 c1 c3 9e 26 00 8b d1 c1 ea 10 30 14 06 8b 55 90 01 01 40 3b c2 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}