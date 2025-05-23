
rule Trojan_Win32_Xorpix_C{
	meta:
		description = "Trojan:Win32/Xorpix.C,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 87 ff 8b 75 10 8b df 03 5d 0c 8a 06 eb [0-06] 30 07 [0-06] 47 46 } //1
		$a_01_1 = {7e 00 41 73 79 6e 63 68 72 6f 6e 6f 75 73 00 90 90 49 6d 70 65 72 73 6f 6e 61 74 65 00 90 77 73 } //1
		$a_01_2 = {90 61 77 69 6e 6c 6f 67 6f 6e 2e 65 78 65 00 90 53 74 61 72 74 75 70 00 90 90 53 68 61 72 65 64 } //1
		$a_01_3 = {e8 00 00 00 00 58 05 0c 00 00 00 50 e9 } //1
		$a_01_4 = {90 61 44 6c 6c 4e 61 6d 65 00 60 90 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}