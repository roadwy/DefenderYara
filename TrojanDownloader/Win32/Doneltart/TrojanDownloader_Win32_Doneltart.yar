
rule TrojanDownloader_Win32_Doneltart{
	meta:
		description = "TrojanDownloader:Win32/Doneltart,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 8b 90 17 03 01 01 01 c3 c5 c6 e8 ?? ?? ?? ?? 90 17 03 01 01 01 bb bd be 01 00 00 00 (eb ?? e9 ??|?? ?? ?? 90) 03 04 08 b0 ?? 8b 45 fc 8a ?? ?? ff 90 03 01 06 e8 [0-10] 8b c3 e8 90 16 90 18 3c 3a 73 03 2c 2f c3 3c 5b 73 06 2c 40 04 0a eb 0c 3c 7b 73 06 2c 60 04 24 eb 02 33 c0 c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}