
rule Trojan_Win32_Redline_BY_MTB{
	meta:
		description = "Trojan:Win32/Redline.BY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f be 14 10 6b d2 2e 81 e2 90 02 04 33 ca 88 4d d7 0f be 45 d7 0f be 4d d7 03 c1 8b 55 0c 03 55 d8 88 02 0f be 45 d7 8b 4d 0c 03 4d d8 0f be 11 2b d0 8b 45 0c 03 45 d8 88 10 eb 90 00 } //2
		$a_01_1 = {f7 f9 6b c0 19 6b c0 11 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a eb } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}