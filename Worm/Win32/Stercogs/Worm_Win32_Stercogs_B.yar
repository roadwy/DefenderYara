
rule Worm_Win32_Stercogs_B{
	meta:
		description = "Worm:Win32/Stercogs.B,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {ff 15 00 e1 40 00 8b 35 04 e2 40 00 6a 03 5f 89 45 ec 89 7d f0 8b 45 ec c7 45 fc 01 00 00 00 8b cf d3 65 fc 85 45 fc 74 76 83 c7 41 57 8d 45 d4 68 c0 e2 40 00 50 ff d6 83 c4 0c 8d 45 d4 50 ff 15 fc e0 40 00 83 f8 02 75 55 57 8d 45 a4 68 b8 e2 40 00 50 ff d6 83 c4 0c 33 c0 50 50 6a 03 50 6a 03 68 00 00 00 80 8d 45 a4 50 ff 15 60 e0 40 00 83 f8 ff 89 45 f8 74 26 } //1
		$a_01_1 = {41 3a 00 00 46 41 54 00 46 41 54 33 32 00 00 00 25 63 3a 5c 25 73 00 00 5c 5c 3f 5c 25 63 3a 00 25 63 3a 5c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}