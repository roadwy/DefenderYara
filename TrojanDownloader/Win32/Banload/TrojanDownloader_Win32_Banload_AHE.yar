
rule TrojanDownloader_Win32_Banload_AHE{
	meta:
		description = "TrojanDownloader:Win32/Banload.AHE,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 eb 05 be 01 00 00 00 b8 ?? ?? ?? ?? 0f b6 44 30 ff 33 d8 8d 45 ?? 50 89 5d ?? c6 45 ?? 00 8d 55 90 1b 02 } //1
		$a_03_1 = {8b 40 20 e8 ?? ?? ?? ?? 83 f8 03 7e 90 14 46 4f 75 ?? 8b 83 ?? ?? 00 00 8b 10 ff 52 14 85 c0 7e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}