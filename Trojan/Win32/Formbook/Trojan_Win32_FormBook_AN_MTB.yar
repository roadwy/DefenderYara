
rule Trojan_Win32_FormBook_AN_MTB{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 06 00 "
		
	strings :
		$a_01_0 = {8a 04 33 2c 33 34 1c 2c 64 34 03 2c 02 88 04 33 46 81 fe de 14 00 00 72 e7 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AN_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {31 45 fc 33 c5 50 89 65 e8 ff 75 f8 8b 45 fc c7 45 fc fe ff ff ff 89 45 f8 8d 45 f0 } //03 00 
		$a_01_1 = {83 c4 08 8b f8 6a 40 68 00 30 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AN_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 03 00 "
		
	strings :
		$a_01_0 = {8b 45 08 83 c0 01 89 45 08 8b 4d 08 0f be 11 85 d2 74 16 8b 45 fc c1 e0 05 03 45 fc 8b 4d 08 0f be 11 03 c2 89 45 fc eb d7 } //03 00 
		$a_01_1 = {89 4d f4 8b 55 f8 8b 45 08 03 42 24 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_FormBook_AN_MTB_4{
	meta:
		description = "Trojan:Win32/FormBook.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 00 55 00 52 00 44 00 45 00 52 00 49 00 4e 00 47 00 53 00 4d 00 41 00 4e 00 44 00 45 00 4e 00 53 00 56 00 45 00 4c 00 53 00 4d 00 41 00 47 00 45 00 4e 00 44 00 45 00 4c 00 49 00 47 00 53 00 59 00 4e 00 4c 00 4f 00 } //01 00 
		$a_01_1 = {52 00 65 00 6b 00 74 00 61 00 6e 00 67 00 65 00 6c 00 65 00 74 00 73 00 6c 00 65 00 76 00 69 00 74 00 61 00 74 00 65 00 64 00 61 00 75 00 74 00 6f 00 74 00 72 00 6f 00 36 00 } //01 00 
		$a_01_2 = {47 00 4c 00 55 00 43 00 4f 00 53 00 45 00 53 00 46 00 55 00 54 00 55 00 52 00 4f 00 4c 00 4f 00 47 00 49 00 53 00 4b 00 45 00 53 00 49 00 4e 00 56 00 4f 00 4c 00 55 00 54 00 45 00 53 00 4f 00 56 00 45 00 52 00 53 00 } //01 00 
		$a_00_3 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //00 00 
	condition:
		any of ($a_*)
 
}