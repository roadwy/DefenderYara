
rule Trojan_BAT_Troob_CCAI_MTB{
	meta:
		description = "Trojan:BAT/Troob.CCAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 06 8f 28 00 00 01 25 71 90 01 04 03 d2 61 d2 81 90 01 04 00 06 17 58 0a 06 02 8e 69 fe 04 0c 08 2d da 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}