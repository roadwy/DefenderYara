
rule TrojanDownloader_Win32_Zlob_BAG{
	meta:
		description = "TrojanDownloader:Win32/Zlob.BAG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {69 c6 44 24 ?? 76 c6 44 24 ?? 64 c6 44 24 ?? 6f c6 44 24 ?? 2e 88 44 24 } //1
		$a_03_1 = {52 c6 84 24 ?? ?? 00 00 55 c6 84 24 ?? ?? 00 00 4c c7 44 24 24 04 01 00 00 ff 15 ?? ?? 40 00 } //1
		$a_03_2 = {65 c6 44 24 ?? 73 88 5c 24 ?? c6 44 24 ?? 72 c6 44 24 ?? 6e c6 44 24 ?? 6c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}