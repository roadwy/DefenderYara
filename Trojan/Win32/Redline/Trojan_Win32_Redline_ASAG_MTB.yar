
rule Trojan_Win32_Redline_ASAG_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 33 d2 f7 75 10 0f b6 92 90 02 04 33 ca 88 4d ff 90 00 } //1
		$a_01_1 = {0f b6 02 03 c1 8b 4d 08 03 4d f4 88 01 8b 55 08 03 55 f4 8a 02 2c 01 8b 4d 08 03 4d f4 88 01 } //1
		$a_01_2 = {48 4a 41 47 41 53 59 55 49 61 67 55 49 38 } //1 HJAGASYUIagUI8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}