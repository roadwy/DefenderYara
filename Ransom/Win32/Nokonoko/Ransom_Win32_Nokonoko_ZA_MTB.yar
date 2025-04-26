
rule Ransom_Win32_Nokonoko_ZA_MTB{
	meta:
		description = "Ransom:Win32/Nokonoko.ZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e9 c1 fa ?? 8b c2 c1 e8 ?? 03 c2 8d 04 c0 03 c0 03 c0 8b d1 2b d0 8a 82 ?? ?? ?? ?? 32 81 ?? ?? ?? ?? 8b 54 24 ?? 88 04 11 41 3b 4c 24 ?? 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}