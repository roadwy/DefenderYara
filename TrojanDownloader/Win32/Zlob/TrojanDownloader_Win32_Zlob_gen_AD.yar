
rule TrojanDownloader_Win32_Zlob_gen_AD{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!AD,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 00 73 00 65 00 61 00 72 00 63 00 68 00 2e 00 70 00 68 00 70 00 3f 00 71 00 71 00 3d 00 25 00 73 00 } //1 /search.php?qq=%s
		$a_00_1 = {61 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 61 00 73 00 73 00 75 00 72 00 61 00 6e 00 63 00 65 00 2e 00 63 00 6f 00 6d 00 } //1 asecurityassurance.com
		$a_00_2 = {8a 16 84 d2 8b c8 74 10 2b f0 32 54 24 0c 88 11 41 8a 14 0e 84 d2 75 f2 c6 01 00 5e c3 } //1
		$a_02_3 = {6a 00 6a 01 ff (15|?? [0-04)] 8d ?? 24 ?? ?? 68 ?? ?? 00 10 ff 15 ?? 90 03 01 01 30 40 00 10 68 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*2) >=3
 
}