
rule TrojanDownloader_BAT_RedLineStealer_KF_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedLineStealer.KF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 28 01 00 00 2b 28 02 00 00 2b [0-15] 28 ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 38 ?? ?? ?? ff 6f ?? ?? ?? 0a 38 ?? ?? ?? ff 0a 38 } //1
		$a_01_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_2 = {42 69 6e 61 72 79 52 65 61 64 65 72 } //1 BinaryReader
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}