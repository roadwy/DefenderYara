
rule PWS_Win32_Trickbot_O{
	meta:
		description = "PWS:Win32/Trickbot.O,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 69 00 6d 00 69 00 6b 00 61 00 74 00 7a 00 } //1 mimikatz
		$a_02_1 = {5b 72 65 66 6c 65 63 74 69 6f 6e 2e 61 73 73 65 6d 62 6c 79 5d 3a 3a 6c 6f 61 64 66 69 6c 65 28 22 [0-20] 5c 6b 65 65 70 61 73 73 2e 65 78 65 22 29 } //1
		$a_01_2 = {4d 54 49 7a 4e 41 3d 3d 3b 20 63 58 64 6c 63 67 3d 3d 3b } //1 MTIzNA==; cXdlcg==;
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}