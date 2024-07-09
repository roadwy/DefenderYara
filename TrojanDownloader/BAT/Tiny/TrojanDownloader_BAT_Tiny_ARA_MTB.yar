
rule TrojanDownloader_BAT_Tiny_ARA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 06 07 11 05 11 06 1b 58 11 04 11 06 59 20 00 10 00 00 3c ?? ?? ?? 00 11 04 11 06 59 38 ?? ?? ?? 00 20 00 10 00 00 16 6f ?? ?? ?? 0a 58 13 06 11 06 11 04 3f ?? ?? ?? ff } //4
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}