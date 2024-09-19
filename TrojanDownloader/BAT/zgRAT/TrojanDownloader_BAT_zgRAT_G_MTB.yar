
rule TrojanDownloader_BAT_ZgRAT_G_MTB{
	meta:
		description = "TrojanDownloader:BAT/ZgRAT.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 11 06 72 ?? ?? 00 70 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 26 20 } //2
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}