
rule TrojanDownloader_BAT_Tiny_AL_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 05 00 00 06 0a 06 03 7d 01 00 00 04 16 06 7b 01 00 00 04 6f 1a 00 00 0a 28 1b 00 00 0a 7e 03 00 00 04 25 2d 17 26 7e 02 00 00 04 fe 06 09 00 00 06 73 1c 00 00 0a 25 80 03 00 00 04 28 01 00 00 2b 06 fe 06 06 00 00 06 73 1e 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 2a } //10
		$a_80_1 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //DownloadString  3
		$a_80_2 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  3
	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3) >=16
 
}