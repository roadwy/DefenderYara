
rule Trojan_BAT_NjRAT_SKBD_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.SKBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 0b 11 0e 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 11 0b 11 0e 17 58 8f ?? 00 00 01 25 71 ?? 00 00 01 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}