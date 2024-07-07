
rule TrojanDownloader_Win32_Thoper_B{
	meta:
		description = "TrojanDownloader:Win32/Thoper.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 46 04 07 30 00 00 } //1
		$a_01_1 = {8b 46 04 3d 09 30 00 } //1
		$a_01_2 = {6b c0 64 03 c1 0f b7 4d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}