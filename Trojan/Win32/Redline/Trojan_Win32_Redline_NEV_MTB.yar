
rule Trojan_Win32_Redline_NEV_MTB{
	meta:
		description = "Trojan:Win32/Redline.NEV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {51 83 65 fc 00 8b 45 0c 90 01 45 fc 8b 45 08 8b 4d fc 31 08 } //1
		$a_03_1 = {8b c1 c1 e8 90 01 01 03 45 90 01 01 03 f2 33 f0 33 75 90 01 01 c7 05 90 01 08 89 75 fc 8b 45 fc 29 45 08 81 45 f4 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}