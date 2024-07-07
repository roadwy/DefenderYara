
rule Trojan_Win32_Redline_MK_MTB{
	meta:
		description = "Trojan:Win32/Redline.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 17 80 07 90 01 01 80 2f 90 01 01 f6 2f 47 e2 f3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Redline_MK_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 8b 45 08 8b 75 0c 8d 55 ec 89 34 24 8a 12 88 54 24 04 89 44 24 08 e8 90 01 04 83 ec 0c 89 45 f8 8b 45 f8 83 c4 20 90 00 } //5
		$a_01_1 = {6a 6d 6e 68 62 67 76 72 79 70 7a 77 6a 62 61 64 7a 62 62 71 79 61 79 } //3 jmnhbgvrypzwjbadzbbqyay
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3) >=8
 
}