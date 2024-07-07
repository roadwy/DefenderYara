
rule Backdoor_Linux_Flashback_B{
	meta:
		description = "Backdoor:Linux/Flashback.B,SIGNATURE_TYPE_MACHOHSTR_EXT,08 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //1 IOPlatformUUID
		$a_01_1 = {00 c7 04 24 0b 00 00 00 e8 50 2e 00 00 b8 68 58 4d 56 bb 12 f7 6c 3c b9 0a 00 00 00 ba 58 56 00 00 } //2
		$a_01_2 = {83 ec 2c c7 44 24 04 b8 73 00 00 8b 45 0c 8b 00 89 04 24 e8 84 45 00 00 89 c3 85 c0 } //2
		$a_01_3 = {8b 85 14 fa ff ff c1 e8 02 ba 15 02 4d 21 f7 e2 c1 ea 04 85 d2 75 0f 89 1c 24 e8 4a 38 00 00 31 ff e9 22 04 00 00 8d 7a ff 69 c2 ec 01 00 00 } //3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*3) >=5
 
}