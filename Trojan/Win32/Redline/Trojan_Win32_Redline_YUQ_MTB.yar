
rule Trojan_Win32_Redline_YUQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.YUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 08 83 c5 90 0a 18 00 81 45 90 01 05 81 6d 90 01 05 8b 45 90 01 01 8b 4d 90 00 } //1
		$a_03_1 = {8b c6 c1 e0 90 01 01 89 45 90 01 01 8b 45 90 01 01 01 45 90 01 01 03 fe 81 3d 90 01 08 75 90 01 01 6a 90 01 01 ff 15 fc 10 40 00 83 0d 90 01 05 31 7d 90 01 01 8b c6 c1 e8 90 01 01 03 45 90 01 01 c7 05 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}