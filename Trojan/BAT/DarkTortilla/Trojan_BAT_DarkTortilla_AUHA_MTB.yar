
rule Trojan_BAT_DarkTortilla_AUHA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.AUHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1d 13 09 2b 8a 11 05 17 d6 13 05 1f ?? 13 09 38 ?? ff ff ff 11 05 11 04 } //5
		$a_03_1 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 1f 09 13 09 38 ?? ff ff ff 11 05 17 d6 13 05 1f 0c 13 09 38 ?? ff ff ff 11 05 11 04 } //5
		$a_03_2 = {02 11 05 02 11 05 91 20 f0 00 00 00 61 b4 9c 19 13 09 2b 8b 11 05 17 d6 13 05 1f 0b 13 09 38 ?? ff ff ff 11 05 11 04 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}