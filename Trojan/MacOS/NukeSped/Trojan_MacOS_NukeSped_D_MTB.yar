
rule Trojan_MacOS_NukeSped_D_MTB{
	meta:
		description = "Trojan:MacOS/NukeSped.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 6f 69 6e 67 6f 74 72 61 64 65 2e 63 6f 6d 2f 75 70 64 61 74 65 5f 63 6f 69 6e 67 6f 74 72 61 64 65 2e 70 68 70 } //01 00 
		$a_00_1 = {2f 70 72 69 76 61 74 65 2f 74 6d 70 2f 75 70 64 61 74 65 63 6f 69 6e 67 6f 74 72 61 64 65 } //01 00 
		$a_00_2 = {69 73 44 6f 77 6e 6c 6f 61 64 } //01 00 
		$a_00_3 = {6b 75 70 61 79 5f 75 70 64 61 74 65 72 5f 6d 61 63 5f 6e 65 77 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_MacOS_NukeSped_D_MTB_2{
	meta:
		description = "Trojan:MacOS/NukeSped.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,05 00 05 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {45 89 ca 41 83 e2 e0 49 8d 5a e0 48 89 d8 48 c1 e8 05 48 ff c0 41 89 c3 41 83 e3 01 48 85 db 0f 84 a0 00 00 00 4c 89 db 48 29 c3 31 c0 0f 28 05 cd 3b 00 00 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 00 } //01 00 
		$a_00_1 = {0f 10 0c 01 0f 10 54 01 10 0f 10 5c 01 20 0f 10 64 01 30 0f 57 c8 0f 57 d0 0f 11 0c 01 0f 11 54 01 10 0f 57 d8 0f 57 e0 0f 11 5c 01 20 0f 11 64 01 30 48 83 c0 40 48 83 c3 02 75 c4 4d 85 db 74 1f } //01 00 
		$a_00_2 = {2f 62 69 6e 2f 62 61 73 68 20 2d 63 } //01 00 
		$a_00_3 = {5f 77 65 62 69 64 65 6e 74 5f 66 } //01 00 
		$a_00_4 = {5f 77 65 62 69 64 65 6e 74 5f 73 } //02 00 
		$a_00_5 = {66 75 64 63 69 74 79 64 65 6c 69 76 65 72 73 2e 63 6f 6d 2f 6e 65 74 2e 70 68 70 } //02 00 
		$a_00_6 = {73 63 74 65 6d 61 72 6b 65 74 73 2e 63 6f 6d 2f 6e 65 74 2e 70 68 70 } //00 00 
	condition:
		any of ($a_*)
 
}