
rule TrojanProxy_Win32_Bunitu_G{
	meta:
		description = "TrojanProxy:Win32/Bunitu.G,SIGNATURE_TYPE_PEHSTR_EXT,14 00 0a 00 06 00 00 "
		
	strings :
		$a_01_0 = {ba fd 13 54 50 89 10 81 00 49 40 00 00 ff 00 ff 00 } //10
		$a_03_1 = {2b d2 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 4a 83 ea 47 4a 4a } //10
		$a_01_2 = {81 2c 24 61 75 17 00 8f 00 c7 40 04 03 34 3f 32 ff 48 04 ff 48 04 81 68 04 9b c7 0b 00 ff 48 04 } //10
		$a_01_3 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8 } //10
		$a_03_4 = {8b 34 8a 03 f5 33 ff c1 cf 13 ac 03 f8 85 c0 75 ?? 3b fb 75 ?? 5a 8b 5a 24 03 dd 66 8b 0c 4b 8b 5a 1c 03 dd 8b 04 8b 8b c8 } //10
		$a_00_5 = {c7 00 3a 2a 3a 45 5a } //10
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_03_4  & 1)*10+(#a_00_5  & 1)*10) >=10
 
}