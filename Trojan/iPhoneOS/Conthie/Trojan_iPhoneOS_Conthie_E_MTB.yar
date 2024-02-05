
rule Trojan_iPhoneOS_Conthie_E_MTB{
	meta:
		description = "Trojan:iPhoneOS/Conthie.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_00_0 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 e8 03 01 aa f3 03 00 aa 1f 20 03 d5 81 4d 1a 58 e0 03 08 aa ed 61 00 94 fd 03 1d aa fd 61 00 94 f4 03 00 aa 60 12 40 f9 1f 20 03 d5 81 59 1a 58 e6 61 00 94 fd 03 1d aa f6 61 00 94 9f 02 00 eb f3 17 9f 1a e7 61 00 94 e0 03 14 aa e5 61 00 94 e0 03 13 aa fd 7b 41 a9 f4 4f c2 a8 c0 03 5f d6 } //01 00 
		$a_00_1 = {73 74 61 72 74 4d 6f 6e 69 74 6f 72 69 6e 67 } //01 00 
		$a_00_2 = {4a 59 53 79 73 74 65 6d 2f 72 65 73 74 49 6e 74 2f 63 6f 6c 6c 65 63 74 2f 70 6f 73 74 44 61 74 61 } //01 00 
		$a_00_3 = {41 42 41 64 64 72 65 73 73 42 6f 6f 6b 43 6f 70 79 41 72 72 61 79 4f 66 41 6c 6c 50 65 6f 70 6c 65 } //01 00 
		$a_00_4 = {61 74 74 65 6d 70 74 73 54 6f 52 65 63 72 65 61 74 65 55 70 6c 6f 61 64 54 61 73 6b 73 46 6f 72 42 61 63 6b 67 72 6f 75 6e 64 53 65 73 73 69 6f 6e 73 } //00 00 
	condition:
		any of ($a_*)
 
}