
rule Ransom_Win32_Trigona_SA_MTB{
	meta:
		description = "Ransom:Win32/Trigona.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0b 8b 1e 30 0c 03 40 83 f8 90 01 01 75 90 01 01 33 c0 8b d0 81 e2 90 01 04 79 90 01 01 4a 83 ca 90 01 01 42 8b 4d 90 01 01 0f b6 14 11 8b 0e 30 14 01 40 83 f8 90 01 01 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}