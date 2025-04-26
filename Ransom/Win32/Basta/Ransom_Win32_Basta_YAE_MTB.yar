
rule Ransom_Win32_Basta_YAE_MTB{
	meta:
		description = "Ransom:Win32/Basta.YAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 46 14 8b 46 4c 33 86 b0 00 00 00 8b 4e 68 35 cf e7 0b 00 89 46 4c a1 ?? ?? ?? ?? 8b 40 44 31 04 11 83 c2 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}