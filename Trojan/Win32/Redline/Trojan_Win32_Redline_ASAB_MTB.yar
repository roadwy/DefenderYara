
rule Trojan_Win32_Redline_ASAB_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {0f b6 02 03 c1 8b 4d 08 03 4d d0 88 01 8b 55 08 03 55 d0 8a 02 2c 01 8b 4d 08 03 4d d0 88 01 } //1
		$a_03_1 = {33 d2 f7 75 10 0f b6 92 [0-04] 33 ca 88 4d cf } //1
		$a_01_2 = {66 6a 6f 67 53 48 67 41 73 67 53 47 48 43 76 67 65 76 78 77 65 79 75 64 79 75 65 } //1 fjogSHgAsgSGHCvgevxweyudyue
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}