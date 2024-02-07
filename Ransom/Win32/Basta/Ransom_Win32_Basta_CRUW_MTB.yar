
rule Ransom_Win32_Basta_CRUW_MTB{
	meta:
		description = "Ransom:Win32/Basta.CRUW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {5c 67 69 74 32 5c 55 6e 69 63 6f 64 65 20 44 65 62 75 67 5c 46 69 6e 67 65 72 54 65 78 74 2e 70 64 62 } //02 00  \git2\Unicode Debug\FingerText.pdb
		$a_01_1 = {56 69 73 69 62 6c 65 45 6e 74 72 79 } //00 00  VisibleEntry
	condition:
		any of ($a_*)
 
}