
rule Ransom_Win32_Conti_AB_MTB{
	meta:
		description = "Ransom:Win32/Conti.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 6e 00 44 00 20 00 46 00 69 00 6c 00 65 00 73 00 } //01 00  DnD Files
		$a_01_1 = {2a 00 2e 00 64 00 6e 00 64 00 } //01 00  *.dnd
		$a_01_2 = {44 00 6e 00 44 00 2e 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 } //01 00  DnD.Document
		$a_00_3 = {76 08 3b f8 0f 82 78 01 00 00 f7 c7 03 00 00 00 75 14 c1 e9 02 83 e2 03 83 f9 08 72 29 f3 a5 } //01 00 
		$a_00_4 = {8d 48 17 83 e1 f0 89 4d f0 c1 f9 04 49 83 f9 20 7d 0e 83 ce ff d3 ee 83 4d f8 ff 89 75 f4 eb 10 83 c1 e0 83 c8 ff 33 f6 d3 e8 89 75 f4 } //00 00 
	condition:
		any of ($a_*)
 
}