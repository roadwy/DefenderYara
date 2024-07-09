
rule TrojanDownloader_Win32_AsyncRAT_D_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 85 67 ff ff ff 04 01 88 85 67 ff ff ff 0f be 85 67 ff ff ff 83 f8 5a 0f ?? ?? ?? ?? ?? 0f be 85 67 ff ff ff 50 68 ?? ad 42 00 8d 4d c8 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 8d 45 c8 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 bc 83 7d bc 00 0f ?? ?? ?? ?? ?? 8b 45 a4 83 c0 01 89 45 a4 8d 45 c8 50 68 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}