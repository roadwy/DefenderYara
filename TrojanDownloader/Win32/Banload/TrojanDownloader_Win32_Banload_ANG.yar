
rule TrojanDownloader_Win32_Banload_ANG{
	meta:
		description = "TrojanDownloader:Win32/Banload.ANG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {46 eb 05 be 01 00 00 00 8b 45 ?? 0f b6 5c 30 ff 33 5d ?? 3b fb 7c 0a 81 c3 ff 00 00 00 2b df eb 02 2b df 8d 45 } //1
		$a_02_1 = {83 38 06 7c 90 14 33 db 6a 00 6a 00 8b c7 e8 ?? ?? ?? ?? 50 8b c6 e8 ?? ?? ?? ?? 50 53 6a 00 e8 ?? ?? ?? ?? 83 f8 20 0f 97 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}