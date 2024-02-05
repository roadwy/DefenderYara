
rule Trojan_BAT_Netwire_SEF_MTB{
	meta:
		description = "Trojan:BAT/Netwire.SEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {06 11 04 02 11 04 91 03 11 04 03 8e b7 5d 91 61 07 11 04 07 8e b7 5d 91 61 9c 11 04 17 d6 13 04 11 04 11 05 31 da } //00 00 
	condition:
		any of ($a_*)
 
}