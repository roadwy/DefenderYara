
rule Ransom_MSIL_Filecoder_DP_MTB{
	meta:
		description = "Ransom:MSIL/Filecoder.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {72 61 6e 73 6f 6d 77 61 72 65 2e 70 64 62 } //01 00  ransomware.pdb
		$a_81_1 = {72 61 6e 73 6f 6d 77 61 72 65 2e 65 78 65 } //01 00  ransomware.exe
		$a_81_2 = {72 61 6e 73 6f 6d 77 61 72 65 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //01 00  ransomware.g.resources
		$a_81_3 = {72 61 6e 73 6f 6d 77 61 72 65 5f 6f 72 5f 73 6f 6d 65 74 68 69 6e 6b 5f 69 64 6b } //01 00  ransomware_or_somethink_idk
		$a_81_4 = {72 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //00 00  ransomware.Properties.Resources
	condition:
		any of ($a_*)
 
}