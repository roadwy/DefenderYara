
rule TrojanDownloader_BAT_AsyncRat_CH_MTB{
	meta:
		description = "TrojanDownloader:BAT/AsyncRat.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 04 11 07 11 04 11 07 91 20 ?? ?? ?? ?? 59 d2 9c 00 11 07 17 58 13 07 11 07 11 04 8e 69 fe 04 13 08 11 08 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}