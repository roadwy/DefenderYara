
rule Trojan_Win32_Aclako_B{
	meta:
		description = "Trojan:Win32/Aclako.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_01_0 = {32 44 24 0f 46 88 07 47 4b 75 e6 0f b7 44 24 14 } //2
		$a_01_1 = {66 31 44 24 14 8b 45 0c 66 39 44 24 14 76 05 66 89 44 24 14 33 c0 66 3b 44 24 14 73 25 8b 7d 08 8d 73 06 0f b7 5c 24 14 } //2
		$a_01_2 = {51 ff 50 40 56 8d 84 24 99 05 00 00 53 50 88 9c 24 a0 05 00 00 e8 } //2
		$a_01_3 = {25 73 25 64 2e 62 61 74 00 } //1
		$a_01_4 = {3c 5f 44 61 74 61 4b 65 79 5f 5f 44 61 74 61 4b 65 79 5f 3e 00 } //1
		$a_01_5 = {6d 6f 6f 6f 2e 63 6f 6d 00 } //1
		$a_01_6 = {62 65 66 73 76 63 2e 65 78 65 00 } //1
		$a_01_7 = {47 6c 6f 62 61 6c 5c 52 54 5f 4d 41 49 4e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}