
rule TrojanDownloader_Win32_Cutwail_gen_B{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 50 72 6f 74 33 00 } //2 屜尮牐瑯3
		$a_01_1 = {43 70 6c 33 32 76 65 72 2e 65 78 65 00 } //1
		$a_01_2 = {72 73 33 32 6e 65 74 2e 65 78 65 00 } //1
		$a_01_3 = {0f be 48 01 83 f9 6e 75 0a c7 05 } //2
		$a_01_4 = {83 f9 4d 75 11 8b 55 fc 0f be 42 01 83 f8 5a } //2
		$a_01_5 = {74 5b c7 85 20 fd ff ff 07 00 01 00 68 c8 02 00 00 6a 00 8d 8d 24 fd ff ff } //2
		$a_03_6 = {73 37 8b 4d fc 81 c1 ?? ?? 00 08 } //2
		$a_01_7 = {c6 45 c8 56 c6 45 c9 69 c6 45 ca 72 } //2
		$a_01_8 = {68 40 24 08 9d } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_03_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*1) >=3
 
}