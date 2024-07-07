
rule Trojan_BAT_OrcusRat_DNC_MTB{
	meta:
		description = "Trojan:BAT/OrcusRat.DNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 07 08 91 6f 90 01 03 0a 00 00 08 25 17 59 0c 16 fe 02 0d 09 2d e8 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}