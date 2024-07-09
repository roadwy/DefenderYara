
rule TrojanDownloader_Win32_Fapack_A{
	meta:
		description = "TrojanDownloader:Win32/Fapack.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 6a 00 6a 00 ff d6 ff d7 0b c0 75 54 8d 85 ?? ?? 00 00 50 ff 95 ?? ?? 00 00 0b c0 74 43 68 99 23 5d d9 50 e8 ?? ?? ff ff 0b c0 74 34 8b f8 68 ad 6d bf e8 53 e8 ?? ?? ff ff 0b c0 74 23 8b f0 6a 00 6a 00 8d 85 ?? ?? 00 00 50 8d 85 ?? ?? 00 00 50 6a 00 ff d7 6a 00 8d 85 ?? ?? 00 00 50 ff d6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}