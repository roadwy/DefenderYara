
rule Trojan_Win32_Storup_B{
	meta:
		description = "Trojan:Win32/Storup.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 5b 0c 8b 5b 14 8b 1b 8b 1b 8b 5b 10 8b c3 8b d8 8b 73 3c 8b 74 1e 78 03 f3 8b 7e 20 03 fb 8b 4e 14 } //1
		$a_01_1 = {2d f8 06 00 00 50 ff 75 f8 ff 57 f8 b9 ff 01 00 00 57 33 c0 8d bd f1 f7 ff ff c6 85 f0 f7 ff ff 00 f3 ab } //1
		$a_01_2 = {68 f8 06 00 00 51 ff 75 f8 ff 57 f0 ff 75 f8 ff 57 e8 8d 95 f0 f7 ff ff ff d2 33 c0 ac 85 c0 75 f9 } //1
		$a_01_3 = {5a 77 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 78 78 78 2e 6a 70 67 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}