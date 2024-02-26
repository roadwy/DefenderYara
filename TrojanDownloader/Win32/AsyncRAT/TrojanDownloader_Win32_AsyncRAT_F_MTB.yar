
rule TrojanDownloader_Win32_AsyncRAT_F_MTB{
	meta:
		description = "TrojanDownloader:Win32/AsyncRAT.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {fe ff ff 28 01 00 00 68 24 01 00 00 6a 00 8d 85 90 01 01 fe ff ff 50 e8 90 01 02 00 00 83 c4 0c 83 a5 90 01 01 fe ff ff 00 8d 85 90 01 01 fe ff ff 50 ff b5 90 01 01 fe ff ff e8 90 01 02 00 00 89 85 90 01 01 fe ff ff eb 90 01 01 8d 90 01 02 fe ff ff 50 ff b5 90 01 01 fe ff ff e8 90 01 02 00 00 89 85 90 01 01 fe ff ff 83 bd 90 01 01 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}