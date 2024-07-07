
rule Trojan_BAT_Injuke_AATX_MTB{
	meta:
		description = "Trojan:BAT/Injuke.AATX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {16 0c 2b 12 00 07 08 06 08 91 02 28 90 01 01 00 00 06 9c 00 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d e4 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}