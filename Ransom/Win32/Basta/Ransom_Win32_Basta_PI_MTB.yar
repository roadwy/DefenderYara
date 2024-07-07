
rule Ransom_Win32_Basta_PI_MTB{
	meta:
		description = "Ransom:Win32/Basta.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e9 05 29 c2 90 13 8a 06 46 90 13 c1 e0 05 29 c2 90 13 41 87 f2 90 13 f3 a4 89 d6 90 13 90 13 31 c0 8a 06 90 13 46 3c 20 90 13 0f 83 94 fc fb ff 08 c0 90 13 0f 84 90 02 04 89 c1 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}