
rule Ransom_Win32_Basta_RU_MTB{
	meta:
		description = "Ransom:Win32/Basta.RU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {36 12 86 d0 b7 a4 7d d4 ?? b1 ?? a0 ?? ?? ?? ?? ?? a7 ?? ?? ?? ?? 30 97 ?? ?? ?? ?? 42 b6 ?? d1 b3 ?? ?? ?? ?? d5 ?? d2 b1 ?? ?? ?? ?? b3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}