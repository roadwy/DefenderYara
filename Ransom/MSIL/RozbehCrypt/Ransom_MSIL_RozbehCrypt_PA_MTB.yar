
rule Ransom_MSIL_RozbehCrypt_PA_MTB{
	meta:
		description = "Ransom:MSIL/RozbehCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {4c 00 4f 00 56 00 45 00 2d 00 4c 00 45 00 54 00 54 00 45 00 52 00 2d 00 46 00 4f 00 52 00 2d 00 59 00 4f 00 55 00 2e 00 54 00 58 00 54 00 2e 00 76 00 62 00 73 00 } //01 00  LOVE-LETTER-FOR-YOU.TXT.vbs
		$a_01_1 = {41 00 6c 00 6c 00 20 00 79 00 6f 00 75 00 72 00 20 00 46 00 69 00 6c 00 65 00 73 00 20 00 68 00 61 00 73 00 20 00 62 00 65 00 65 00 6e 00 20 00 45 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 20 00 62 00 79 00 20 00 52 00 6f 00 7a 00 62 00 65 00 68 00 20 00 52 00 61 00 6e 00 73 00 6f 00 6d 00 77 00 61 00 72 00 65 00 } //01 00  All your Files has been Encrypted by Rozbeh Ransomware
		$a_01_2 = {5c 45 76 69 6c 4e 6f 6d 69 6e 61 74 75 73 2e 70 64 62 } //00 00  \EvilNominatus.pdb
	condition:
		any of ($a_*)
 
}