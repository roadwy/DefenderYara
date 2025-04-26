
rule MonitoringTool_MacOS_Spyrix_C_MTB{
	meta:
		description = "MonitoringTool:MacOS/Spyrix.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f4 4f be a9 fd 7b 01 a9 fd 43 00 91 f3 03 01 aa f4 03 00 aa 20 11 00 f0 00 a0 28 91 63 58 fc 97 e2 03 00 aa 08 80 5f f8 03 01 40 f9 e0 03 14 aa e1 03 13 aa fd 7b 41 a9 f4 4f c2 a8 60 00 1f d6 } //1
		$a_01_1 = {ff 03 02 d1 fc 6f 02 a9 fa 67 03 a9 f8 5f 04 a9 f6 57 05 a9 f4 4f 06 a9 fd 7b 07 a9 fd c3 01 91 28 11 00 d0 08 0d 46 f9 93 02 08 8b e1 23 00 91 e0 03 13 aa 02 00 80 d2 03 00 80 d2 9b a4 05 94 73 02 40 f9 68 fe 7e d3 a8 0c 00 b5 68 e2 7d 92 14 09 40 f9 e0 03 13 aa 41 00 80 52 9f a4 05 94 34 0d 00 b4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}