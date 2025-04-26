
rule TrojanDownloader_Win32_Banload_XK{
	meta:
		description = "TrojanDownloader:Win32/Banload.XK,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 6d 72 49 6e 63 72 54 69 6d 65 72 } //3 TmrIncrTimer
		$a_01_1 = {47 42 78 4f 72 67 6d } //2 GBxOrgm
		$a_01_2 = {54 46 72 6d 55 4e 53 } //2 TFrmUNS
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=7
 
}