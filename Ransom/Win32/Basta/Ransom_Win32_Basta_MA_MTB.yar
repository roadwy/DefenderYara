
rule Ransom_Win32_Basta_MA_MTB{
	meta:
		description = "Ransom:Win32/Basta.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {33 ca 58 2b c1 46 03 d0 89 35 90 01 04 a1 90 01 04 89 15 90 01 04 88 1c 06 8b 15 90 01 04 42 89 15 90 01 04 81 fd 10 52 00 00 0f 8c 90 00 } //02 00 
		$a_03_1 = {83 c6 04 0f af 5d 38 8b 45 0c 2d 90 01 04 31 85 a0 00 00 00 8b 45 60 8b d3 c1 ea 08 88 14 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}