
rule TrojanDownloader_Win32_Unruy_F{
	meta:
		description = "TrojanDownloader:Win32/Unruy.F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f8 44 0f 85 90 01 04 a1 90 01 04 03 85 90 01 04 0f b6 40 ff 83 f8 43 0f 85 90 01 04 a1 90 01 04 03 85 90 01 04 0f b6 40 fe 83 f8 46 90 00 } //1
		$a_03_1 = {ff 70 50 8b 45 90 01 01 ff 70 34 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}