
rule Trojan_Win32_Redline_GBI_MTB{
	meta:
		description = "Trojan:Win32/Redline.GBI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 11 88 55 f3 0f be 45 f3 0f be 4d f3 8b 55 f4 83 e2 90 01 01 8b 75 08 0f be 14 16 33 ca 03 c1 8b 4d 0c 03 4d f4 88 01 0f be 55 f3 8b 45 0c 03 45 f4 0f be 08 2b ca 8b 55 0c 03 55 f4 88 0a eb aa 90 00 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}