
rule Ransom_MSIL_Yikes_PAA_MTB{
	meta:
		description = "Ransom:MSIL/Yikes.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 61 6e 73 6f 6d 77 61 72 65 50 4f 43 } //01 00  RansomwarePOC
		$a_01_1 = {45 4e 43 52 59 50 54 45 44 5f 46 49 4c 45 5f 45 58 54 45 4e 53 49 4f 4e } //01 00  ENCRYPTED_FILE_EXTENSION
		$a_81_2 = {79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //01 00  your files have been encrypted
		$a_81_3 = {5c 5f 5f 5f 52 45 43 4f 56 45 52 5f 5f 46 49 4c 45 53 5f 5f 2e 79 69 6b 65 73 2e 74 78 74 } //00 00  \___RECOVER__FILES__.yikes.txt
	condition:
		any of ($a_*)
 
}