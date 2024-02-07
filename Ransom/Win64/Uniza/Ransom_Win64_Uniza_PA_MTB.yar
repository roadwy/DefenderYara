
rule Ransom_Win64_Uniza_PA_MTB{
	meta:
		description = "Ransom:Win64/Uniza.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 4e 49 5a 41 20 52 41 4e 53 4f 4d 57 41 52 45 } //01 00  UNIZA RANSOMWARE
		$a_01_1 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 65 6e 63 72 79 70 74 65 64 } //01 00  All your files were encrypted
		$a_01_2 = {61 64 76 61 6e 63 65 64 20 63 72 79 70 74 6f 67 72 61 70 68 69 63 20 74 65 63 68 6e 6f 6c 6f 67 79 } //01 00  advanced cryptographic technology
		$a_01_3 = {70 61 79 20 74 68 65 20 72 61 6e 73 6f 6d 20 61 6e 64 20 44 4d 20 6d 65 } //01 00  pay the ransom and DM me
		$a_01_4 = {52 65 6c 65 61 73 65 5c 52 61 6e 73 2e 70 64 62 } //00 00  Release\Rans.pdb
	condition:
		any of ($a_*)
 
}