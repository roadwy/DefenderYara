
rule Trojan_Win32_Redline_GCA_MTB{
	meta:
		description = "Trojan:Win32/Redline.GCA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 4d d7 8b 45 d8 33 d2 f7 75 10 0f b6 92 90 01 04 33 ca 88 4d df 8b 45 0c 03 45 d8 8a 08 88 4d d6 90 00 } //10
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 76 00 62 00 63 00 2e 00 65 00 78 00 65 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1) >=11
 
}