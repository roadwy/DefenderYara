
rule Trojan_Win32_Mupad_G{
	meta:
		description = "Trojan:Win32/Mupad.G,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 00 ff 15 90 01 03 00 6a 00 ff 15 90 01 03 00 83 f8 23 74 08 6a 00 ff 15 90 01 03 00 6a 00 ff 15 90 00 } //1
		$a_03_1 = {6a 04 68 00 10 00 00 68 40 1f 00 00 6a 00 ff 15 90 01 03 00 89 45 fc 8b 4d fc 89 4d b8 33 d2 8b 4d f4 e8 90 00 } //1
		$a_03_2 = {85 c0 75 09 b9 40 00 00 00 51 ff 75 c8 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d bc 42 74 90 01 01 6a 04 68 00 10 00 00 68 00 10 00 00 6a 00 ff 15 90 00 } //4
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*4) >=5
 
}