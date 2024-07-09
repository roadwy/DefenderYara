
rule TrojanDownloader_BAT_BitRAT_A_MTB{
	meta:
		description = "TrojanDownloader:BAT/BitRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 04 06 91 20 92 ?? 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}