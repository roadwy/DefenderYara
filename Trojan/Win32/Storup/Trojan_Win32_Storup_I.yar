
rule Trojan_Win32_Storup_I{
	meta:
		description = "Trojan:Win32/Storup.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8d 0c 07 8b 84 24 14 01 00 00 0f b6 44 04 10 03 c2 23 c6 8a 44 04 10 30 01 47 3b 7d 0c (72|7c) 96 } //1
		$a_01_1 = {b8 4d 5a 00 00 66 39 45 00 75 f1 56 8b 75 3c 03 f5 81 3e 50 45 00 00 74 07 } //1
		$a_01_2 = {8b 06 8b 48 28 85 c9 74 18 8b 46 04 03 c1 74 11 6a ff 6a 01 6a 00 ff d0 } //1
		$a_02_3 = {00 2e 00 64 00 61 00 74 00 00 90 09 40 00 [0-20] (00 5c 00 6d 00 73 00 68 00 74 00 6d 00 6c 00 2e 00 64 00 6c 00 6c 00 00|00 5c 00 69 00 65 00 66 00 72 00 61 00 6d 00 65 00 2e 00 64 00 6c 00 6c 00 00) } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}