
rule Trojan_WinNT_Almanahe_B_sys{
	meta:
		description = "Trojan:WinNT/Almanahe.B!sys,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {89 7e 1c 8b 7e 18 32 d2 8b ce ff 15 68 2b 01 00 8b c7 5f 5e c2 08 00 4b 00 65 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 } //1
		$a_01_1 = {00 72 00 69 00 70 00 74 00 6f 00 72 00 54 00 61 00 62 00 6c 00 65 00 00 00 00 00 5c 00 52 00 45 00 47 00 49 00 53 00 54 00 52 00 59 00 5c 00 4d 00 41 00 43 00 48 00 49 00 4e 00 45 00 5c 00 53 } //1
		$a_01_2 = {6f 6f 74 5c 73 79 73 74 65 6d 33 32 5c 25 73 00 55 8b ec 81 ec 48 01 00 00 53 56 57 68 44 64 6b } //1
		$a_01_3 = {39 3e 75 54 81 7e 18 73 45 72 76 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}