
rule Trojan_Win32_Emotet_VDK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VDK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_00_0 = {8b 44 24 18 33 d2 8d 0c 03 8b c3 f7 74 24 20 8b 44 24 14 8a 04 50 30 01 } //2
		$a_00_1 = {8b c6 33 d2 f7 f3 83 c6 01 8a 44 55 00 30 44 3e ff 3b 74 24 1c 75 } //2
		$a_00_2 = {0f b6 04 37 01 d8 25 ff 00 00 00 8a 04 07 8b 5c 24 20 32 04 0b 8b 74 24 1c 88 04 0e } //2
		$a_02_3 = {69 c0 fd 43 03 00 a3 90 01 04 81 05 90 01 04 c3 9e 26 00 0f b7 05 90 01 04 25 ff 7f 00 00 90 09 05 00 a1 90 00 } //1
		$a_02_4 = {30 04 1e 46 3b f7 7c 90 09 05 00 e8 90 00 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=2
 
}