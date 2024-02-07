
rule Ransom_MSIL_WPlague_DD_MTB{
	meta:
		description = "Ransom:MSIL/WPlague.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {52 61 73 6f 6d 77 61 72 65 32 2e 30 } //01 00  Rasomware2.0
		$a_81_1 = {50 72 61 6e 73 6f 6d 77 61 72 65 } //01 00  Pransomware
		$a_81_2 = {50 72 61 6e 73 6f 6d 77 61 72 65 5f 4c 6f 61 64 } //01 00  Pransomware_Load
		$a_81_3 = {52 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //01 00  Ransomware.Properties.Resources
		$a_81_4 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 77 69 74 68 20 73 70 65 63 69 61 6c 20 65 6e 63 72 79 70 74 69 6f 6e 20 70 72 6f 67 72 61 6d 2e } //00 00  files have been encrypted with special encryption program.
	condition:
		any of ($a_*)
 
}