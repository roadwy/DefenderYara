
rule Trojan_BAT_Barys_PTGK_MTB{
	meta:
		description = "Trojan:BAT/Barys.PTGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {ff ff 11 34 28 90 01 01 00 00 06 80 03 00 00 04 11 39 20 7f 16 21 66 5a 20 b6 c8 80 bb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}