
rule Trojan_Win32_Bnserv_A{
	meta:
		description = "Trojan:Win32/Bnserv.A,SIGNATURE_TYPE_PEHSTR_EXT,08 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 62 00 6e 00 73 00 65 00 72 00 76 00 34 00 00 00 } //1
		$a_01_1 = {31 72 65 70 6c 79 46 69 6e 69 73 68 65 64 28 51 4e 65 74 77 6f 72 6b 52 65 70 6c 79 2a 29 00 } //1
		$a_03_2 = {68 74 74 70 3a 2f 2f [0-20] 2f 70 6c 61 6e ?? 2e 78 6d 6c 00 } //1
		$a_01_3 = {26 61 63 74 69 6f 6e 3d 67 65 74 26 69 64 3d 00 72 65 73 2e 70 68 70 3f 6b 65 79 3d 00 00 00 00 63 61 70 63 68 61 4b 65 79 } //5
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*5) >=3
 
}