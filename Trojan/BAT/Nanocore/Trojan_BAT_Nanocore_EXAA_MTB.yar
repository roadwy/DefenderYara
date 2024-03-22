
rule Trojan_BAT_Nanocore_EXAA_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.EXAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 01 11 0a 11 10 11 08 5d d2 9c } //01 00 
		$a_01_1 = {11 0c 11 0d 61 13 0f } //01 00 
		$a_01_2 = {11 01 11 0b 91 11 08 58 13 0e } //00 00 
	condition:
		any of ($a_*)
 
}