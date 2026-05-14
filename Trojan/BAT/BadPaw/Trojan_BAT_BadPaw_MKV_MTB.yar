
rule Trojan_BAT_BadPaw_MKV_MTB{
	meta:
		description = "Trojan:BAT/BadPaw.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 07 00 9c 20 c8 00 00 00 38 05 e9 ff ff 11 08 1f 09 11 00 1a 91 9c 20 62 00 00 00 28 ?? 00 00 06 39 ed e8 ff ff 26 20 37 00 00 00 38 e2 e8 ff ff fe 0c 04 00 20 04 00 00 00 20 db 00 00 00 20 49 00 00 00 59 9c 20 ed 00 00 00 28 ?? 00 00 06 39 be e8 ff ff 26 20 9c 00 00 00 38 b3 e8 ff ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}