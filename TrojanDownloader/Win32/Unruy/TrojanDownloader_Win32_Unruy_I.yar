
rule TrojanDownloader_Win32_Unruy_I{
	meta:
		description = "TrojanDownloader:Win32/Unruy.I,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6a 44 6a 46 6a 30 6a 34 [0-2f] 81 c4 a0 00 00 00 8d [0-09] 68 03 00 1f 00 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}