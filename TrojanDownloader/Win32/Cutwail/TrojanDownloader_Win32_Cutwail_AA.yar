
rule TrojanDownloader_Win32_Cutwail_AA{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 64 ff 35 18 00 00 00 58 5d c3 } //1
		$a_03_1 = {c7 45 e0 b9 79 37 9e (ff 75 e0|58 8b 45 e0) } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}