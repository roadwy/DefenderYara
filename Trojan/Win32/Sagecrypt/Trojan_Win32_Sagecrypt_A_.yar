
rule Trojan_Win32_Sagecrypt_A_{
	meta:
		description = "Trojan:Win32/Sagecrypt.A!!Sagecrypt.gen!A,SIGNATURE_TYPE_ARHSTR_EXT,28 00 28 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {61 63 79 22 20 3a 20 00 6c 61 74 22 20 3a 20 00 6c 6e 67 22 20 3a 20 } //0a 00 
		$a_00_1 = {25 73 5c 66 25 75 2e 76 62 73 } //0a 00  %s\f%u.vbs
		$a_00_2 = {73 74 00 5c 5c 3f 5c 25 53 00 25 73 5c 66 25 75 2e 68 74 61 } //0a 00  瑳尀㽜╜S猥晜甥栮慴
		$a_00_3 = {7a 68 00 61 72 00 65 6e 00 64 65 00 65 73 00 66 61 00 66 72 00 69 74 00 6b 72 00 6e 6c 00 70 74 00 68 69 00 76 69 00 74 72 00 6d 73 00 6e 6f } //05 00 
	condition:
		any of ($a_*)
 
}