
rule Trojan_Win32_Zbot_AP_MTB{
	meta:
		description = "Trojan:Win32/Zbot.AP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 88 13 01 00 05 b1 96 07 00 2d 2a 93 07 00 89 d1 51 6a 40 68 00 30 00 00 50 83 ec 04 c7 04 24 00 00 00 00 ff 15 } //2
		$a_01_1 = {88 d7 02 3e 81 c6 72 c4 0c 00 81 ee 71 c4 0c 00 88 3f 00 1f 83 c7 01 83 ec 04 89 14 24 } //1
		$a_01_2 = {8b 14 24 83 c4 04 2d 71 e7 0c 00 05 75 e7 0c 00 c1 ea 08 81 ed df c3 05 00 81 c5 e0 c3 05 00 39 c5 75 0c bd d2 71 bf 7f 89 ea bd 00 00 00 00 81 c1 3d f5 09 00 81 e9 3e f5 09 00 83 f9 00 75 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}