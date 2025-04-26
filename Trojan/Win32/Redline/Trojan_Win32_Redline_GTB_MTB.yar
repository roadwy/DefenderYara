
rule Trojan_Win32_Redline_GTB_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 45 c0 0f b6 08 8b 45 c0 33 d2 be 04 00 00 00 f7 f6 8b 45 10 0f b6 14 10 33 ca 88 4d c7 8b 45 08 03 45 c0 8a 4d c7 88 08 eb 64 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 [0-20] 5c 00 52 00 65 00 67 00 53 00 76 00 63 00 73 00 2e 00 65 00 78 00 65 00 } //1
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}