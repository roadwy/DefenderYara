
rule Trojan_BAT_Heracles_NF_MTB{
	meta:
		description = "Trojan:BAT/Heracles.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {09 08 5d 13 08 07 11 08 91 11 04 09 1f 16 5d 91 61 13 09 } //00 00 
	condition:
		any of ($a_*)
 
}