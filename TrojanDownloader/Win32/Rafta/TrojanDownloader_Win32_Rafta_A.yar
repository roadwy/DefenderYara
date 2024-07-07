
rule TrojanDownloader_Win32_Rafta_A{
	meta:
		description = "TrojanDownloader:Win32/Rafta.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {33 c0 8a 8b f0 9e 00 00 8b bd 90 01 04 30 0c 38 40 3d 00 10 00 00 72 f5 8a 0f 90 00 } //10
		$a_03_1 = {80 78 02 0e 75 90 01 01 c6 46 02 0e c6 46 03 02 39 bb a0 97 00 00 75 90 01 01 c6 46 03 03 90 00 } //1
		$a_03_2 = {80 78 02 0a 75 90 01 01 c6 46 02 0a c6 46 03 02 83 bb a0 97 00 00 01 75 90 01 01 c6 46 03 03 90 00 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}