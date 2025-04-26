
rule TrojanDownloader_Win32_Zlob_ANV{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ANV,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 84 24 4e 05 00 00 52 c6 84 24 4d 05 00 00 55 c6 84 24 4f 05 00 00 4c c7 44 24 24 04 01 00 00 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}