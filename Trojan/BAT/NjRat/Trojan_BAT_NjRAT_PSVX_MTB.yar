
rule Trojan_BAT_NjRAT_PSVX_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PSVX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 08 16 6f 90 01 01 00 00 0a 13 05 12 05 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 16 28 90 01 01 00 00 06 39 c5 ff ff ff 26 20 04 00 00 00 fe 0e 0a 00 28 90 01 01 00 00 06 39 8b ff ff ff 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}