
rule Trojan_BAT_RedLine_RDDX_MTB{
	meta:
		description = "Trojan:BAT/RedLine.RDDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {06 07 1f 0a 5d 91 61 d2 81 90 01 04 07 17 58 0b 07 03 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}