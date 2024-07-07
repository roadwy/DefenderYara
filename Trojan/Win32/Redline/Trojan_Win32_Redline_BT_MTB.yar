
rule Trojan_Win32_Redline_BT_MTB{
	meta:
		description = "Trojan:Win32/Redline.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {f7 f6 0f b6 92 90 02 04 33 ca 88 4d ff 8b 45 f8 8a 88 90 02 04 88 4d fd 0f b6 55 ff 8b 45 f8 0f b6 88 90 02 04 03 ca 8b 55 f8 88 8a 90 00 } //1
		$a_03_1 = {8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 f8 0f b6 82 90 02 04 2b c1 8b 4d f8 88 81 90 02 04 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Redline_BT_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.BT!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e8 89 45 f8 8b 45 d4 01 45 f8 8b 45 f8 33 45 e8 81 45 e0 47 86 c8 61 31 45 fc 2b 5d fc ff 4d d8 89 35 84 bf 44 00 89 5d dc 0f 85 b6 fe ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}