
rule Ransom_MSIL_HydraCrypt_DA_MTB{
	meta:
		description = "Ransom:MSIL/HydraCrypt.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {2f 43 20 76 73 73 61 64 6d 69 6e 2e 65 78 65 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 71 75 69 65 74 } //01 00  /C vssadmin.exe delete shadows /all /quiet
		$a_81_1 = {2f 43 20 77 6d 69 63 20 73 68 61 64 6f 77 63 6f 70 79 20 64 65 6c 65 74 65 } //01 00  /C wmic shadowcopy delete
		$a_81_2 = {64 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //01 00  do not try to rename encrypted files
		$a_81_3 = {41 6c 67 6f 72 69 74 68 6d 73 20 75 73 65 64 20 61 72 65 20 41 45 53 20 61 6e 64 20 52 53 41 } //00 00  Algorithms used are AES and RSA
	condition:
		any of ($a_*)
 
}