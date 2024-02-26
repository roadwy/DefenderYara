
rule Trojan_BAT_DarkCloud_CRAA_MTB{
	meta:
		description = "Trojan:BAT/DarkCloud.CRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}