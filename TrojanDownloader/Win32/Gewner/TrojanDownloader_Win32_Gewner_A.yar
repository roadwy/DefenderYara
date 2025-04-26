
rule TrojanDownloader_Win32_Gewner_A{
	meta:
		description = "TrojanDownloader:Win32/Gewner.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6e 65 77 67 2f 67 65 74 55 70 64 61 74 65 2e 70 68 70 } //1 newg/getUpdate.php
		$a_00_1 = {63 6f 6e 66 69 67 5c 73 76 63 68 6f 73 74 2e 65 78 65 } //1 config\svchost.exe
		$a_02_2 = {8a 17 83 fe 1f 7c 02 33 f6 2a 96 ?? ?? ?? ?? 32 96 ?? ?? ?? ?? 46 8b c8 80 e1 01 80 f9 01 75 0c } //1
		$a_00_3 = {83 ca fe 42 85 d2 75 0e 8a 10 2a 14 31 f6 d2 32 14 31 88 10 eb 0a } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}