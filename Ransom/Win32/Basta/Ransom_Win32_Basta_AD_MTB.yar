
rule Ransom_Win32_Basta_AD_MTB{
	meta:
		description = "Ransom:Win32/Basta.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 f6 39 74 24 ?? 76 ?? b8 ?? ?? ?? ?? 8b ce f7 ee c1 fa 03 8b c2 c1 e8 1f 03 c2 6b c0 ?? 2b c8 8b 44 24 ?? 8a 89 ?? ?? ?? ?? 32 8e ?? ?? ?? ?? 88 0c 06 46 3b 74 24 ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}