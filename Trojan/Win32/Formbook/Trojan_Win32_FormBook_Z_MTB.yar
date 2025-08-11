
rule Trojan_Win32_FormBook_Z_MTB{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3c 30 50 4f 53 54 74 09 40 } //1
		$a_01_1 = {04 83 c4 0c 83 06 07 5b 5f 5e 8b e5 5d c3 8b 17 03 55 0c 6a 01 83 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FormBook_Z_MTB_2{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {74 0a 4e 0f b6 08 8d 44 08 01 75 f6 8d 70 01 0f b6 00 8d 55 } //1
		$a_01_1 = {1a d2 80 e2 af 80 c2 7e eb 2a 80 fa 2f 75 11 8a d0 80 e2 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_FormBook_Z_MTB_3{
	meta:
		description = "Trojan:Win32/FormBook.Z!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 0a 00 00 "
		
	strings :
		$a_01_0 = {03 c8 0f 31 2b c1 89 45 fc } //1
		$a_01_1 = {3c 24 0f 84 76 ff ff ff 3c 25 74 94 } //1
		$a_01_2 = {3b 4f 14 73 95 85 c9 74 91 } //1
		$a_01_3 = {3c 69 75 44 8b 7d 18 8b 0f } //1
		$a_01_4 = {5d c3 8d 50 7c 80 fa 07 } //1
		$a_01_5 = {0f be 5c 0e 01 0f b6 54 0e 02 83 e3 0f c1 ea 06 } //1
		$a_01_6 = {57 89 45 fc 89 45 f4 89 45 f8 } //1
		$a_01_7 = {66 89 0c 02 5b 8b e5 5d } //1
		$a_01_8 = {3c 54 74 04 3c 74 75 f4 } //1
		$a_01_9 = {56 68 03 01 00 00 8d 85 95 fe ff ff 6a 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=2
 
}