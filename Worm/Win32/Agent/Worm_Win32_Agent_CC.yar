
rule Worm_Win32_Agent_CC{
	meta:
		description = "Worm:Win32/Agent.CC,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 06 00 00 "
		
	strings :
		$a_02_0 = {bb 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 1a ff 2b d3 90 03 05 05 81 ea 90 01 04 83 ea 90 01 01 e8 90 01 02 ff ff 8b 55 f4 8d 45 f8 e8 90 01 02 ff ff 43 4e 75 90 03 01 01 d9 dc 90 00 } //10
		$a_00_1 = {41 76 65 6e 67 65 72 20 62 79 20 4e 68 54 } //10 Avenger by NhT
		$a_00_2 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 } //1 explorer.exe
		$a_00_3 = {73 76 63 68 6f 73 74 2e 65 78 65 } //1 svchost.exe
		$a_00_4 = {68 61 68 61 2e 65 78 65 } //1 haha.exe
		$a_00_5 = {6d 73 6e 77 6f 72 6d 2e 65 78 65 } //1 msnworm.exe
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=21
 
}