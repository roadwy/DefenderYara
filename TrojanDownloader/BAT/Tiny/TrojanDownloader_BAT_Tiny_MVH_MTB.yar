
rule TrojanDownloader_BAT_Tiny_MVH_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.MVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 01 00 00 70 72 71 00 00 70 6f 04 00 00 0a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}