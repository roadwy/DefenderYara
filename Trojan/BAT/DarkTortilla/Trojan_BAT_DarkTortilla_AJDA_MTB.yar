
rule Trojan_BAT_DarkTortilla_AJDA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AJDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 13 04 1c 13 07 2b 8f 11 04 1f 09 5d 16 fe 01 13 05 11 05 2c 08 1d 13 07 38 ?? ff ff ff 1a 2b f6 08 74 ?? 00 00 1b 07 75 ?? 00 00 1b 11 04 91 20 c9 00 00 00 61 b4 6f ?? 01 00 0a 1e 13 07 38 ?? ff ff ff 17 13 07 38 ?? ff ff ff 08 75 ?? 00 00 1b 07 74 ?? 00 00 1b 11 04 91 6f ?? 01 00 0a 17 13 07 38 ?? ff ff ff 11 04 17 d6 13 04 1c 13 07 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}