
rule Trojan_Win32_Redline_GCR_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c0 29 c8 88 45 e3 8b 4d e4 0f b6 45 e3 31 c8 88 45 e3 0f b6 45 e3 2d 90 01 04 88 45 e3 8a 4d e3 8b 45 e4 88 4c 05 e9 8b 45 e4 83 c0 90 01 01 89 45 e4 90 00 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 41 00 70 00 70 00 4c 00 61 00 75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}