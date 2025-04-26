
rule Worm_Win32_Lamin_C{
	meta:
		description = "Worm:Win32/Lamin.C,SIGNATURE_TYPE_PEHSTR,06 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 70 72 65 61 64 5f 44 69 67 73 62 79 } //1 Spread_Digsby
		$a_01_1 = {53 70 72 65 61 64 5f 47 6f 6f 67 6c 65 54 61 6c 6b } //1 Spread_GoogleTalk
		$a_01_2 = {47 61 6e 79 61 6e 67 20 4d 61 6c 69 6e 67 73 69 61 } //1 Ganyang Malingsia
		$a_01_3 = {47 00 65 00 74 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 4e 00 61 00 6d 00 65 00 } //1 GetExtensionName
		$a_01_4 = {53 00 70 00 65 00 63 00 69 00 61 00 6c 00 46 00 6f 00 6c 00 64 00 65 00 72 00 73 00 } //1 SpecialFolders
		$a_01_5 = {04 5c ff ff 41 44 ff 6a 00 28 dc fe 01 00 5d fb 2f cc fe 04 5c ff ff 41 ac fe 6a 00 28 bc fe 03 00 5d fb 2f 9c fe } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}