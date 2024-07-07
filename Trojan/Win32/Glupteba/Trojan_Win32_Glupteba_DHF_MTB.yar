
rule Trojan_Win32_Glupteba_DHF_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 7d 0c 00 7c 26 8b 55 90 01 01 03 55 90 01 01 0f be 1a e8 90 01 04 0f b6 c0 33 d8 8b 4d 90 01 01 03 4d 90 01 01 88 19 8b 55 0c 83 ea 01 89 55 0c eb d4 90 00 } //1
		$a_02_1 = {33 d2 b9 00 01 00 00 f7 f1 89 15 90 01 04 81 3d 90 01 04 21 06 00 00 75 1f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}