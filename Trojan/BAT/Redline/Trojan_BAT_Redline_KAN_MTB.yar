
rule Trojan_BAT_Redline_KAN_MTB{
	meta:
		description = "Trojan:BAT/Redline.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {11 05 11 13 7e 90 01 01 00 00 04 28 90 01 01 00 00 06 a5 90 01 01 00 00 01 61 d2 81 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}