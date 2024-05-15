
rule Ransom_Win32_Basta_RT_MTB{
	meta:
		description = "Ransom:Win32/Basta.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f af c5 2b 05 90 01 04 33 d8 a1 90 01 04 8b b0 90 01 04 8b 50 90 01 01 8b 44 24 90 01 01 0b d3 0f af 35 90 01 04 03 88 90 01 04 0b 48 90 01 01 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}