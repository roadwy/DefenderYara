
rule Trojan_BAT_Marsilia_PTGD_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 1a 00 00 01 0a 03 28 90 01 01 00 00 0a 0b 28 90 01 01 00 00 0a 0c 08 28 90 01 01 00 00 0a 02 6f 26 00 00 0a 6f 27 00 00 0a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}