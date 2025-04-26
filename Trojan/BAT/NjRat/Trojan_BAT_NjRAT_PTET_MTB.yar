
rule Trojan_BAT_NjRAT_PTET_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 44 1f 14 1f 2d 28 ?? 00 00 06 2b 1d 06 28 ?? 00 00 06 20 bf 02 00 00 20 b4 02 00 00 28 ?? 00 00 06 0b 07 2c 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}