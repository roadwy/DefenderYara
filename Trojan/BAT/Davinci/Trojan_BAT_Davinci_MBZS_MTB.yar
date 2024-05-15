
rule Trojan_BAT_Davinci_MBZS_MTB{
	meta:
		description = "Trojan:BAT/Davinci.MBZS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 8e 69 5d 91 13 90 02 0c 61 11 90 02 04 59 20 00 01 00 00 58 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}