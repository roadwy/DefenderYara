
rule Trojan_BAT_Zilla_MKV_MTB{
	meta:
		description = "Trojan:BAT/Zilla.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 a1 01 00 00 03 28 ?? 00 00 0a 13 00 20 02 00 00 00 38 d0 ff ff ff 04 28 ?? 00 00 0a 13 01 20 00 00 00 00 7e 25 03 00 04 7b e8 02 00 04 39 b4 ff ff ff 26 20 00 00 00 00 38 a9 ff ff ff 11 04 2a 00 11 02 6f ?? 00 00 0a 13 08 20 00 00 00 00 7e 25 03 00 04 7b 37 03 00 04 39 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 05 00 45 01 00 00 00 05 00 00 00 38 00 00 00 00 00 11 08 02 16 02 8e 69 6f ?? 00 00 0a 13 04 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}