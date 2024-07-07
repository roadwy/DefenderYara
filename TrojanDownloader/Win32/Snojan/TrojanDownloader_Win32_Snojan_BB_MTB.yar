
rule TrojanDownloader_Win32_Snojan_BB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Snojan.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 18 83 78 20 00 75 06 83 78 2c 00 74 26 8b 55 ec 39 50 1c 7f 1e 7c 08 8b 55 e8 39 50 18 73 14 3b 06 75 04 89 1e eb 02 89 1f ff 4e 0c } //1
		$a_01_1 = {77 65 63 61 6e 2e 68 61 73 74 68 65 2e 74 65 63 68 6e 6f 6c 6f 67 79 2f 75 70 6c 6f 61 64 } //1 wecan.hasthe.technology/upload
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}