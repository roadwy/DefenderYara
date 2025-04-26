
rule TrojanDownloader_Win32_Bodsuds_A{
	meta:
		description = "TrojanDownloader:Win32/Bodsuds.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3b c6 74 67 8d 8c 24 ?? ?? 00 00 2b c1 40 50 8b c1 50 8d 84 24 ?? ?? 00 00 50 ff 15 } //1
		$a_01_1 = {ff 54 24 30 85 c0 74 0b ff 44 24 10 83 7c 24 10 14 7c da } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}