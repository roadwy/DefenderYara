
rule TrojanDownloader_Win32_Adload_H{
	meta:
		description = "TrojanDownloader:Win32/Adload.H,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 6a 41 51 8d 55 ?? 8b cc 89 a5 ?? ff ff ff 52 e8 ?? ?? 00 00 8b ce e8 ?? ?? ff ff 8b 4d ?? 8d 85 ?? ?? ff ff 6a 01 50 6a 00 51 68 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 8d 4d ?? c6 45 fc 3a } //1
		$a_03_1 = {c6 45 fc 9b e8 ?? ?? ff ff 6a 2f 8d 8d ?? ff ff ff c6 45 fc 9d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}