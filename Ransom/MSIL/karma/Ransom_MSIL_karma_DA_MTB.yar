
rule Ransom_MSIL_karma_DA_MTB{
	meta:
		description = "Ransom:MSIL/karma.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {59 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  Your files have been encrypted
		$a_81_1 = {44 45 43 52 59 50 54 20 4d 59 20 46 49 4c 45 53 } //01 00  DECRYPT MY FILES
		$a_81_2 = {6b 61 72 6d 61 20 44 65 63 72 79 70 74 6f 72 } //01 00  karma Decryptor
		$a_81_3 = {6b 61 72 6d 61 20 52 61 6e 73 6f 6d 77 61 72 65 } //01 00  karma Ransomware
		$a_81_4 = {54 65 61 6d 20 4b 61 72 6d 61 } //00 00  Team Karma
	condition:
		any of ($a_*)
 
}