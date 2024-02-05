
rule Trojan_BAT_ClipBanker_NEE_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.NEE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {06 07 9a 0c 08 6f 19 00 00 0a 02 28 1c 00 00 0a 2c 1d 08 72 0b 00 00 70 6f 1d 00 00 0a 72 5b 00 00 70 6f 1e 00 00 0a 14 14 6f 18 00 00 0a 26 07 17 58 0b 07 06 8e 69 32 c7 } //00 00 
	condition:
		any of ($a_*)
 
}