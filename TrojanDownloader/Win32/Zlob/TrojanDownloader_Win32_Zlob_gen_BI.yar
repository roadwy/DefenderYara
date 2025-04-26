
rule TrojanDownloader_Win32_Zlob_gen_BI{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!BI,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 05 6a 01 52 ff 15 ?? ?? 40 00 85 c0 75 34 } //2
		$a_01_1 = {5f 5f 49 53 41 5f 55 50 44 41 54 45 5f 5f 00 } //1
		$a_01_2 = {5f 5f 43 48 45 43 4b 5f 5f 00 } //1 彟䡃䍅彋_
		$a_01_3 = {2f 69 6e 64 65 78 2e 70 68 70 3f 62 3d 31 26 74 3d 25 64 26 71 3d 7b 73 65 61 72 63 68 54 65 72 6d 73 7d } //1 /index.php?b=1&t=%d&q={searchTerms}
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}