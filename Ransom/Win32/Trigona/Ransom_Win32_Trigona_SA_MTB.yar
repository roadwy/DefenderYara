
rule Ransom_Win32_Trigona_SA_MTB{
	meta:
		description = "Ransom:Win32/Trigona.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0b 8b 1e 30 0c 03 40 83 f8 ?? 75 ?? 33 c0 8b d0 81 e2 ?? ?? ?? ?? 79 ?? 4a 83 ca ?? 42 8b 4d ?? 0f b6 14 11 8b 0e 30 14 01 40 83 f8 ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}