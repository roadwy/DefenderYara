
rule Ransom_Win32_LockCrypt_MAK_MTB{
	meta:
		description = "Ransom:Win32/LockCrypt.MAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {64 6f 77 6e 6c 6f 61 64 20 6b 65 79 20 6f 6b } //01 00  download key ok
		$a_81_1 = {41 74 74 65 6e 74 69 6f 6e 21 21 21 20 59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 20 21 21 21 } //01 00  Attention!!! Your files are encrypted !!!
		$a_81_2 = {54 6f 20 72 65 63 6f 76 65 72 20 66 69 6c 65 73 2c 20 66 6f 6c 6c 6f 77 20 74 68 65 20 70 72 6f 6d 70 74 73 20 69 6e 20 74 68 65 20 74 65 78 74 20 66 69 6c 65 } //01 00  To recover files, follow the prompts in the text file
		$a_81_3 = {76 73 73 61 64 6d 69 6e 20 64 65 6c 65 74 65 20 73 68 61 64 6f 77 73 20 2f 61 6c 6c } //01 00  vssadmin delete shadows /all
		$a_81_4 = {44 6f 20 6e 6f 74 20 72 65 6e 61 6d 65 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //00 00  Do not rename encrypted files
		$a_00_5 = {5d 04 00 } //00 6d 
	condition:
		any of ($a_*)
 
}