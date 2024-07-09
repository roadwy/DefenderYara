
rule TrojanDownloader_Win32_Zlob_JN{
	meta:
		description = "TrojanDownloader:Win32/Zlob.JN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 1c 07 32 18 8b 06 88 1c 01 41 83 f9 0b 72 ed } //1
		$a_03_1 = {10 75 2b 09 1d ?? ?? ?? 10 83 65 fc 00 8d 45 ?? 50 8d 45 ?? 50 b9 ?? ?? ?? 10 e8 ?? ?? ff ff 68 ?? ?? ?? 10 e8 ?? ?? ?? 00 83 4d fc ff } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}