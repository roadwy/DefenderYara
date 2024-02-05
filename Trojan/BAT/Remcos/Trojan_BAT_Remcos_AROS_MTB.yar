
rule Trojan_BAT_Remcos_AROS_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AROS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {26 07 8e 69 17 59 0d 2b 21 0a 2b dc 0b 2b ed 0c 2b ef 07 08 91 13 04 07 08 07 09 91 9c 07 09 11 04 9c 08 17 58 0c 09 17 59 0d 08 09 32 e4 } //00 00 
	condition:
		any of ($a_*)
 
}