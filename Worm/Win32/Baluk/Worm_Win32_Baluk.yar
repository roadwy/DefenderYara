
rule Worm_Win32_Baluk{
	meta:
		description = "Worm:Win32/Baluk,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ba 00 3a 00 5c 00 b9 00 c6 00 c6 00 cb 00 c3 00 c6 00 be 00 2e 00 ba 00 bd 00 be 00 00 00 00 00 } //1
		$a_01_1 = {5c 00 ec 00 f1 00 e9 00 5c 00 } //1
		$a_01_2 = {66 3d b3 00 7c 1c 66 3d fd 00 7f 16 8b 55 d8 52 ff d3 66 2d 83 00 0f 80 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}