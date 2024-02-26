
rule Ransom_Linux_RagnarLocker_D_MTB{
	meta:
		description = "Ransom:Linux/RagnarLocker.D!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {2e 52 47 4e 52 5f 45 53 58 49 } //01 00  .RGNR_ESXI
		$a_00_1 = {55 73 61 67 65 3a 20 25 73 20 2d 73 6c 65 65 70 20 4e 2d 6d 69 6e 20 61 6e 64 2f 6f 72 20 2f 70 61 74 68 2f 74 6f 2f 62 65 2f 65 6e 63 72 79 70 74 65 64 } //01 00  Usage: %s -sleep N-min and/or /path/to/be/encrypted
		$a_00_2 = {52 47 4e 52 5f 4e 4f 54 45 53 } //01 00  RGNR_NOTES
		$a_00_3 = {2e 76 6d 64 6b } //01 00  .vmdk
		$a_00_4 = {45 4e 43 5f 46 49 4c 45 53 } //01 00  ENC_FILES
		$a_00_5 = {2e 6f 6e 69 6f 6e 2f 63 6c 69 65 6e 74 2f } //00 00  .onion/client/
	condition:
		any of ($a_*)
 
}