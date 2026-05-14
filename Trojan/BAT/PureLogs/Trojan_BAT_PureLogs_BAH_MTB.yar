
rule Trojan_BAT_PureLogs_BAH_MTB{
	meta:
		description = "Trojan:BAT/PureLogs.BAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2d 0b 11 08 17 58 13 08 38 84 fd ff ff 11 0c 20 aa 00 00 00 61 20 aa 00 00 00 61 d2 13 0c 11 0d 19 62 11 0d 1b 63 60 20 ff 00 00 00 5f d2 13 0d 11 0d 19 63 11 0d 1b 62 60 20 ff 00 00 00 5f d2 13 0d 11 0e 66 66 d2 13 0e 06 11 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}