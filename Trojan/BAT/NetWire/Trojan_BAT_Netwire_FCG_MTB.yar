
rule Trojan_BAT_Netwire_FCG_MTB{
	meta:
		description = "Trojan:BAT/Netwire.FCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 8e b7 5d 91 } //01 00 
		$a_03_1 = {8e b7 5d 91 61 8c 90 01 03 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}