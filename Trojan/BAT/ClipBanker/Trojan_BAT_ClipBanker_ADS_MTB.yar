
rule Trojan_BAT_ClipBanker_ADS_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ADS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 0c 00 00 6f ?? ?? ?? 0a fe 0c 02 00 20 01 00 00 00 fe 0e 04 00 20 fd ff ff ff 20 ac d2 1d 60 20 fc 18 6a 37 61 20 50 ca 77 57 40 10 00 00 00 20 02 00 00 00 fe 0e 04 00 fe 1c 18 00 00 01 58 00 58 fe 0e 02 00 fe 0c 02 00 00 23 00 00 00 00 00 00 00 40 23 00 00 00 00 00 00 14 40 5a 28 ?? ?? ?? 0a 3f 94 ff ff ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}