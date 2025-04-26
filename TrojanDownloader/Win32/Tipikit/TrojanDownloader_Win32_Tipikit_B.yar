
rule TrojanDownloader_Win32_Tipikit_B{
	meta:
		description = "TrojanDownloader:Win32/Tipikit.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2d 41 75 07 e8 ?? ?? ff ff eb 33 e8 ?? ?? ff ff 83 3d ?? ?? 40 00 00 75 00 eb 1a 68 ?? ?? 00 00 90 09 07 00 66 81 3d ?? ?? 40 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}