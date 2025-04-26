
rule TrojanDownloader_Win32_AsyncRat_CCHD_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRat.CCHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f8 ff 15 ?? ?? ?? ?? ff d6 2b c7 2d ?? ?? ?? ?? 99 8b fa 8b f0 57 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 f7 2b f7 83 c4 0c 83 fe 64 7e 14 68 } //1
		$a_01_1 = {73 61 6e 64 62 6f 78 21 21 21 } //1 sandbox!!!
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}