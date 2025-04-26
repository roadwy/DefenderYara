
rule TrojanDownloader_Win32_Kuluoz_A{
	meta:
		description = "TrojanDownloader:Win32/Kuluoz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 45 fc c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 2e c6 85 ?? ?? ff ff 38 c6 85 ?? ?? ff ff 78 c6 85 ?? ?? ff ff 00 } //1
		$a_03_1 = {83 c4 08 c6 45 ?? 2e c6 45 ?? 65 c6 45 ?? 78 c6 45 ?? 65 c6 45 ?? 00 8d 4d 90 1b 00 51 8b 55 ?? 52 ff 55 } //1
		$a_03_2 = {c6 40 01 68 8b 8d ?? ?? ff ff 03 8d ?? ?? ff ff 8b 55 ?? 89 51 02 8b 85 90 1b 00 ff ff 03 85 90 1b 01 ff ff c6 40 06 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}