
rule TrojanDownloader_Win32_Waski_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Waski.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ba 00 00 00 00 8b 45 0c c1 e8 02 2b c1 50 f7 f3 42 42 29 16 33 d2 58 f7 f3 03 14 24 52 81 04 24 21 ec 30 45 5a 31 16 83 c6 04 e2 d4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}