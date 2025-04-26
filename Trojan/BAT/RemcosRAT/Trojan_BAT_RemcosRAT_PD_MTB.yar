
rule Trojan_BAT_RemcosRAT_PD_MTB{
	meta:
		description = "Trojan:BAT/RemcosRAT.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 26 00 00 0a 02 0e 04 03 8e 69 6f 27 00 00 0a 0a 06 0b 2b 00 07 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}