
rule Trojan_BAT_NjRat_ABUA_MTB{
	meta:
		description = "Trojan:BAT/NjRat.ABUA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 03 00 fe 0c 02 00 9a fe 0e 01 00 fe 0c 00 00 fe 0c 01 00 20 02 00 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a fe 0e 00 00 fe 0c 02 00 20 01 00 00 00 d6 fe 0e 02 00 fe 0c 02 00 fe 0c 03 00 8e b7 3f ?? ff ff ff fe 0c 00 00 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 14 14 6f ?? 00 00 0a 26 2a } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}