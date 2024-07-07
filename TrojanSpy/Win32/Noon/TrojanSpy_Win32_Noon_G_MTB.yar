
rule TrojanSpy_Win32_Noon_G_MTB{
	meta:
		description = "TrojanSpy:Win32/Noon.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {33 d2 8b c1 f7 f3 8b 45 90 01 01 41 8a 54 15 90 01 01 30 54 01 ff 3b 4c 37 fc 72 90 00 } //1
		$a_02_1 = {33 d2 8b c1 f7 f6 8b 45 90 01 01 41 8a 54 15 90 01 01 30 54 01 ff 3b 4c 3b 90 01 01 72 90 00 } //1
		$a_02_2 = {83 e1 03 74 90 01 01 8a 16 88 17 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}