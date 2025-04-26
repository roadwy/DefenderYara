
rule TrojanDownloader_Win32_AsyncRAT_F_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe ff ff 28 01 00 00 68 24 01 00 00 6a 00 8d 85 ?? fe ff ff 50 e8 ?? ?? 00 00 83 c4 0c 83 a5 ?? fe ff ff 00 8d 85 ?? fe ff ff 50 ff b5 ?? fe ff ff e8 ?? ?? 00 00 89 85 ?? fe ff ff eb ?? 8d ?? ?? fe ff ff 50 ff b5 ?? fe ff ff e8 ?? ?? 00 00 89 85 ?? fe ff ff 83 bd ?? fe ff ff } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}