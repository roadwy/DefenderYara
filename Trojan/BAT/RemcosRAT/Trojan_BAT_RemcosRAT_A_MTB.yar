
rule Trojan_BAT_RemcosRAT_A_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 09 17 6f 90 01 01 00 00 0a 09 16 6f 90 01 01 00 00 0a 09 0b 07 28 90 01 01 00 00 0a 0c 28 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}