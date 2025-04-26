
rule TrojanDownloader_Win32_PurityScan_MI_MTB{
	meta:
		description = "TrojanDownloader:Win32/PurityScan.MI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 fb 8b fe 2b f9 c1 e2 ?? 8d 9a ?? ?? ?? 00 8d 04 0f 6a ?? 99 5d f7 fd 8a 82 ?? ?? ?? 00 8b 54 24 ?? 32 01 ff 44 24 ?? 41 39 74 24 ?? 88 04 13 } //1
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 43 6c 69 63 6b 53 70 72 69 6e 67 } //1 SOFTWARE\ClickSpring
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}