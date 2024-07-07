
rule Ransom_Win32_Basta_RU_MTB{
	meta:
		description = "Ransom:Win32/Basta.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 12 86 d0 b7 a4 7d d4 90 01 01 b1 90 01 01 a0 90 01 05 a7 90 01 04 30 97 90 01 04 42 b6 90 01 01 d1 b3 90 01 04 d5 90 01 01 d2 b1 90 01 04 b3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}