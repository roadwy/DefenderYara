
rule TrojanDownloader_BAT_Tnega_ABNK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tnega.ABNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 16 31 07 06 28 ?? ?? ?? 0a 2a 14 2a 90 0a 31 00 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 06 6f } //3
		$a_01_1 = {52 65 70 6c 61 63 65 } //1 Replace
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}