
rule Trojan_BAT_Barys_GPA_MTB{
	meta:
		description = "Trojan:BAT/Barys.GPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d 90 02 20 17 58 09 5d 91 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}