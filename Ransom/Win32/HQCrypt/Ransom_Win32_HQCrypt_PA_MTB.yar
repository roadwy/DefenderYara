
rule Ransom_Win32_HQCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/HQCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 48 6f 77 20 74 6f 20 64 65 63 72 79 70 74 20 66 69 6c 65 73 2e 68 74 6d 6c } //01 00  \How to decrypt files.html
		$a_01_1 = {41 4c 4c 20 59 4f 55 52 20 50 45 52 53 4f 4e 41 4c 20 46 49 4c 45 53 20 41 52 45 20 45 4e 43 52 59 50 54 45 44 } //01 00  ALL YOUR PERSONAL FILES ARE ENCRYPTED
		$a_01_2 = {5c 61 6c 2d 6d 61 64 61 6e 69 5c 52 65 6c 65 61 73 65 5c 48 51 5f 35 32 5f 34 32 2e 70 64 62 } //00 00  \al-madani\Release\HQ_52_42.pdb
	condition:
		any of ($a_*)
 
}