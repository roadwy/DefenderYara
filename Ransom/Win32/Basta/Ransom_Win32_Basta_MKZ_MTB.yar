
rule Ransom_Win32_Basta_MKZ_MTB{
	meta:
		description = "Ransom:Win32/Basta.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {ac 02 c3 e9 34 c9 fc ff } //01 00 
		$a_01_1 = {fc 32 c3 e9 bc 6a ff ff } //01 00 
		$a_01_2 = {c0 c8 ee 90 e9 82 1f 03 00 } //01 00 
		$a_01_3 = {8b c0 90 e9 b9 17 fd ff } //01 00 
		$a_01_4 = {aa 49 e9 44 14 02 00 } //05 00 
		$a_01_5 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //00 00  VisibleEntry
	condition:
		any of ($a_*)
 
}