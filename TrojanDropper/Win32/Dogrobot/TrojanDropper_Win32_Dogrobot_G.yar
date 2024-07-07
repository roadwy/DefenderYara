
rule TrojanDropper_Win32_Dogrobot_G{
	meta:
		description = "TrojanDropper:Win32/Dogrobot.G,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {85 c0 0f 84 90 01 02 00 00 81 7d 90 01 01 02 76 19 89 0f 85 90 01 02 00 00 8b 45 0c 39 45 90 01 01 74 90 00 } //2
		$a_03_1 = {c1 ee 0b 0f af f7 39 75 10 73 90 01 01 8b d6 be 00 08 00 00 2b f7 c1 fe 05 03 f0 d1 e3 90 00 } //2
		$a_03_2 = {8b 5d 10 8b d3 83 c2 3c 8b 90 01 01 03 90 01 01 83 c3 18 83 c3 10 8b 1b 8b 4d 0c 03 cb 90 00 } //1
		$a_00_3 = {5c 5c 2e 5c 50 63 69 46 74 44 69 73 6b } //1 \\.\PciFtDisk
		$a_00_4 = {25 63 3a 5c 50 72 6f 67 72 61 6d 20 66 69 6c 65 73 5c 4d 53 44 4e } //1 %c:\Program files\MSDN
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}