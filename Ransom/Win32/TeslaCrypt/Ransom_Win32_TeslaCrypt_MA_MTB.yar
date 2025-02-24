
rule Ransom_Win32_TeslaCrypt_MA_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.MA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 be af c4 00 00 29 c6 89 d0 19 c8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}