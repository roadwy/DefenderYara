
rule Ransom_Win32_Genasom_HE{
	meta:
		description = "Ransom:Win32/Genasom.HE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_11_0 = {45 f4 eb 02 eb 10 48 c1 e8 0f c1 e0 0f 0f b7 08 81 e9 4d 5a 00 00 0b c9 75 01 } //00 2e 
		$a_5c_1 = {69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 5c 52 } //65 6c 
		$a_61_2 = {65 5c 53 69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 2e 70 64 62 00 00 a9 75 00 00 70 00 00 00 45 3a 5c 5c 57 4f 52 4b 5c 5c 57 4f 52 4b 5f 50 45 43 45 50 42 5c 5c 57 6f 72 6b 5f 32 30 31 32 20 50 72 69 76 61 74 65 5c 5c 2e 2a 5c 5c 53 69 6c 65 6e 63 65 5f 6c 6f 63 6b 5f 62 6f 74 5c 5c 53 69 6c 65 6e } //63 65 
	condition:
		any of ($a_*)
 
}