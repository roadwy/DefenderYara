
rule Ransom_Win32_Basta_SI_MTB{
	meta:
		description = "Ransom:Win32/Basta.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e0 8d 76 ?? b8 ?? ?? ?? ?? f7 ef 03 d7 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 6b c0 ?? 2b c8 8b 45 ?? 8a 8c 39 ?? ?? ?? ?? 32 8f ?? ?? ?? ?? 47 88 4c 06 ?? 3b 7d ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}