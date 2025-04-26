
rule TrojanProxy_Win32_Bunitu_E{
	meta:
		description = "TrojanProxy:Win32/Bunitu.E,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {ba 19 20 54 50 89 10 81 00 2d 34 00 00 ff 00 ff 00 } //1
		$a_01_1 = {c6 41 06 4d c6 41 0f 53 41 } //1
		$a_01_2 = {c7 40 04 69 6c 33 32 ff 48 04 ff 48 04 83 68 04 01 ff 48 04 } //2
		$a_01_3 = {c7 00 3a 2a 3a 45 } //2
		$a_01_4 = {77 72 72 72 2f 31 2e 30 20 32 30 30 20 4f 4b } //2 wrrr/1.0 200 OK
		$a_01_5 = {c7 40 04 60 4f 3f 32 ff 48 04 ff 48 04 81 68 04 f8 e2 0b 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1) >=6
 
}