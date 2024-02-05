
rule Ransom_Win32_Basta_PA_MTB{
	meta:
		description = "Ransom:Win32/Basta.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 c1 88 85 90 01 04 0f b7 95 90 01 04 0f b7 45 8c 2b d0 8b 8d 90 01 04 66 89 11 0f b6 55 87 33 95 90 01 04 88 55 87 8b 45 f4 0f b6 08 8b 95 90 01 04 0f b6 02 0b c8 88 4d 90 00 } //01 00 
		$a_03_1 = {d3 fa 88 55 90 01 01 8b 8d 90 01 04 8b 11 8b 4d dc d3 e2 89 95 90 01 04 8b 45 d0 33 45 b8 89 85 90 01 04 8b 8d 90 01 04 8b 11 23 55 d4 8b 45 c4 89 10 8b 0d 90 01 04 8b 55 d4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}