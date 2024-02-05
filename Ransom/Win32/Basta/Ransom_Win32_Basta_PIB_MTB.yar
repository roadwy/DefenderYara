
rule Ransom_Win32_Basta_PIB_MTB{
	meta:
		description = "Ransom:Win32/Basta.PIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 34 18 a1 90 01 04 8b 1d 90 01 04 35 90 01 04 03 c8 0f af de a1 90 01 04 2b 05 90 01 04 35 90 01 04 89 0d 90 01 04 01 05 90 01 04 a1 90 01 04 8b cb c1 e9 10 88 0c 02 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}