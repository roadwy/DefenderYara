
rule Ransom_MSIL_Parasite_MK_MTB{
	meta:
		description = "Ransom:MSIL/Parasite.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2a 00 2a 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 62 65 74 61 72 61 73 69 74 65 } //0a 00  .betarasite
		$a_81_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //0a 00  vssadmin.exe delete shadows /all /quiet
		$a_81_2 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //0a 00  wbadmin delete catalog -quiet
		$a_81_3 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //0a 00  All your files are encrypted
		$a_81_4 = {66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 52 43 34 20 61 6e 64 20 52 53 41 2d 32 30 34 38 } //01 00  files have been encrypted using RC4 and RSA-2048
		$a_81_5 = {59 4f 55 52 20 50 45 52 53 4f 4e 4e 41 4c 20 53 45 53 53 49 4f 4e 20 49 44 3a } //00 00  YOUR PERSONNAL SESSION ID:
		$a_00_6 = {78 0d 01 00 34 00 34 00 07 00 00 01 00 09 81 01 2e 70 61 72 61 73 69 74 65 0a 00 27 81 01 76 73 73 61 64 6d 69 6e 2e 65 } //78 65 
	condition:
		any of ($a_*)
 
}
rule Ransom_MSIL_Parasite_MK_MTB_2{
	meta:
		description = "Ransom:MSIL/Parasite.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 07 00 00 01 00 "
		
	strings :
		$a_81_0 = {2e 70 61 72 61 73 69 74 65 } //0a 00  .parasite
		$a_81_1 = {76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //0a 00  vssadmin.exe delete shadows /all /quiet
		$a_81_2 = {77 62 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 63 61 74 61 6c 6f 67 20 2d 71 75 69 65 74 } //0a 00  wbadmin delete catalog -quiet
		$a_81_3 = {59 6f 75 72 20 49 44 20 69 73 3a } //0a 00  Your ID is:
		$a_81_4 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //0a 00  All your files are encrypted
		$a_81_5 = {41 6c 6c 20 79 6f 75 72 20 66 69 6c 65 73 20 68 61 76 65 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 20 75 73 69 6e 67 20 52 53 41 2d 32 30 34 38 20 61 6e 64 20 52 43 34 20 65 6e 63 72 79 70 74 69 6f 6e 20 61 6c 67 6f 72 69 74 68 6d } //01 00  All your files have been encrypted using RSA-2048 and RC4 encryption algorithm
		$a_81_6 = {40 52 45 41 44 5f 4d 45 5f 46 49 4c 45 5f 45 4e 43 52 59 50 54 45 44 40 2e 68 74 6d 6c } //00 00  @READ_ME_FILE_ENCRYPTED@.html
		$a_00_7 = {5d 04 00 00 4d 6a 04 80 5c 39 00 00 4e 6a 04 80 00 00 01 00 25 00 23 00 54 72 6f 6a 61 6e 44 72 6f 70 70 65 72 3a 4f 39 } //37 4d 
	condition:
		any of ($a_*)
 
}