
rule TrojanDownloader_Win32_Skreed_A{
	meta:
		description = "TrojanDownloader:Win32/Skreed.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2f 64 6c 2f 65 78 2e 70 68 70 3f } //1 /dl/ex.php?
		$a_03_1 = {8b d8 56 53 ff 15 ?? ?? ?? ?? 53 89 45 08 ff d7 81 7d 08 01 04 00 00 73 0d 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 81 7d 08 00 04 00 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}