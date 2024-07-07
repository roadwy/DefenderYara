
rule TrojanSpy_Win32_Banker_SW{
	meta:
		description = "TrojanSpy:Win32/Banker.SW,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {94 14 85 c9 74 0c 39 08 75 08 89 cf 8b 41 fc 4a eb 02 31 c0 8b 4c 94 14 85 c9 74 0b } //1
		$a_00_1 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e } //1 INOVANDOOOO...
		$a_00_2 = {70 72 6f 6a 65 63 74 73 5c 6e 6f 76 6f 62 68 6f } //1 projects\novobho
		$a_02_3 = {6d 61 69 6c 61 67 65 6e 74 90 02 1b 68 65 6c 6f 6e 61 6d 65 90 02 1b 75 73 65 65 68 6c 6f 90 00 } //1
		$a_00_4 = {62 61 6e 63 6f } //1 banco
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}