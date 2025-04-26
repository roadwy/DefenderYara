
rule TrojanDownloader_Win32_Zlob_gen_CU{
	meta:
		description = "TrojanDownloader:Win32/Zlob.gen!CU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {ff 4c 24 10 75 f0 90 09 0a 00 8a 90 04 01 04 04 1c 0c 14 ?? 32 90 04 01 04 44 5c 4c 54 24 ?? 88 } //1
		$a_03_1 = {6a 01 68 00 04 00 00 ff 15 ?? ?? ?? ?? 48 48 f7 d8 1b c0 f7 d0 23 44 24 10 3b ?? 89 44 24 10 75 18 8d 84 24 ?? ?? 00 00 50 ff 74 24 18 ff 54 24 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}