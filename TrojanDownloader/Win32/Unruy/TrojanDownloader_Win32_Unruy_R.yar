
rule TrojanDownloader_Win32_Unruy_R{
	meta:
		description = "TrojanDownloader:Win32/Unruy.R,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {30 01 00 00 e8 ?? ?? 00 00 3b ?? 90 13 8d } //1
		$a_01_1 = {3d 00 28 00 00 72 } //1 =(爀
		$a_03_2 = {3d ff 7f 00 00 89 [0-04] 75 ?? c7 [0-03] fe 7f 00 00 db } //1
		$a_03_3 = {83 f8 03 74 ?? (83 f8 01|3b c5) 8d [0-05] 75 ?? e8 ?? ?? 00 00 85 c0 75 ?? 8d [0-05] e8 ?? ?? 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}