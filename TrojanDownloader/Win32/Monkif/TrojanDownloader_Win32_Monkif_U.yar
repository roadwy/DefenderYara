
rule TrojanDownloader_Win32_Monkif_U{
	meta:
		description = "TrojanDownloader:Win32/Monkif.U,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 2a c2 2c ?? 42 3b 54 24 10 88 01 7c } //1
		$a_03_1 = {33 c0 8a c8 80 e9 ?? 30 88 ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7c } //1
		$a_01_2 = {6d 73 79 75 76 2e 64 6c 6c 00 45 78 70 6f 72 74 31 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}