
rule TrojanDownloader_Win32_QuasarRAT_B_MTB{
	meta:
		description = "TrojanDownloader:Win32/QuasarRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 b9 00 10 00 00 8b 45 90 01 01 03 c1 89 45 90 01 01 03 d9 89 5d 90 01 01 83 d6 90 01 01 89 75 90 01 01 2b f9 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}