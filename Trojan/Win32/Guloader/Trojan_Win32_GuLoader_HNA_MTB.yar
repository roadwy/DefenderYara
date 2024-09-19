
rule Trojan_Win32_GuLoader_HNA_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_01_0 = {ae 98 75 9e 8a 6d 00 00 00 be b4 b1 b8 af ad e0 } //10
		$a_01_1 = {ea 9d 12 f3 b0 14 f9 c4 16 ee c4 1b bd 95 4b 8c 77 69 88 73 67 86 73 68 82 6f 64 80 71 6b 00 00 } //5
		$a_01_2 = {83 e9 30 2c 53 c6 45 d6 04 f6 d8 1b c0 f7 d0 23 c1 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1) >=16
 
}