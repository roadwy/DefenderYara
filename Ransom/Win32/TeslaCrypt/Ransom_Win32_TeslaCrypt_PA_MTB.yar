
rule Ransom_Win32_TeslaCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/TeslaCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6c 6c 20 6f 66 20 79 6f 75 72 20 66 69 6c 65 73 20 77 65 72 65 20 70 72 6f 74 65 63 74 65 64 20 62 79 20 61 20 73 74 72 6f 6e 67 20 65 6e 63 72 79 70 74 69 6f 6e 20 77 69 74 68 20 52 53 41 2d 32 30 34 38 } //01 00  All of your files were protected by a strong encryption with RSA-2048
		$a_01_1 = {73 68 61 64 6f 77 73 20 2f 61 6c 6c 20 2f 51 75 69 65 74 } //01 00  shadows /all /Quiet
		$a_01_2 = {25 00 73 00 5c 00 72 00 65 00 73 00 74 00 6f 00 72 00 65 00 5f 00 66 00 69 00 6c 00 65 00 73 00 5f 00 25 00 73 00 2e 00 68 00 74 00 6d 00 6c 00 } //01 00  %s\restore_files_%s.html
		$a_03_3 = {64 6a 64 6b 64 75 65 70 36 32 6b 7a 34 6e 7a 78 2e 90 02 20 2f 69 6e 73 74 2e 70 68 70 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}