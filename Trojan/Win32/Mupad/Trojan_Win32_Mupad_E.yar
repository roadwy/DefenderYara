
rule Trojan_Win32_Mupad_E{
	meta:
		description = "Trojan:Win32/Mupad.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {3a 2f 2f 6e 69 67 68 74 73 74 6f 72 6d 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //2 ://nightstorm.gdn/index.htm
		$a_00_1 = {68 74 74 70 3a 2f 2f 6d 61 79 66 61 6d 69 6c 79 73 74 72 65 6e 67 74 68 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //2 http://mayfamilystrength.gdn/index.htm
		$a_00_2 = {2f 2f 72 65 6d 61 69 6e 66 72 61 6d 65 2e 67 64 6e 2f 69 6e 64 65 78 2e 68 74 6d } //2 //remainframe.gdn/index.htm
		$a_02_3 = {63 72 79 70 74 3d 90 02 06 3b 67 2e 6c 69 63 65 6e 63 65 76 69 6f 6c 65 74 2e 67 64 6e 90 00 } //2
		$a_02_4 = {70 72 6f 74 6f 63 6f 6c 3d 76 35 90 02 08 26 65 68 3d 90 02 08 26 76 3d 90 02 08 6d 69 64 3d 90 00 } //2
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*2+(#a_02_4  & 1)*2) >=3
 
}
rule Trojan_Win32_Mupad_E_2{
	meta:
		description = "Trojan:Win32/Mupad.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 e8 90 01 01 04 00 00 dd d8 83 c4 08 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 90 01 02 40 00 90 00 } //1
		$a_03_1 = {6a 00 ff 15 90 01 02 40 00 83 f8 23 74 08 6a 00 ff 15 90 01 02 40 00 8b 90 02 01 c8 90 02 08 00 6a 00 ff 15 90 01 02 40 00 90 00 } //1
		$a_03_2 = {c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d b8 42 74 90 01 01 ff 15 90 01 02 40 00 90 00 } //1
		$a_03_3 = {6a 0a ff 15 90 01 02 40 00 6a 00 ff 15 90 01 02 40 00 85 c0 75 1c 8b 90 02 04 40 00 89 90 01 01 b8 8b 90 01 01 b8 ff d1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}