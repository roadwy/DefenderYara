
rule Trojan_BAT_StealC_B_MTB{
	meta:
		description = "Trojan:BAT/StealC.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 0b 11 0c 58 11 06 11 0c 91 52 11 0c 17 58 13 0c 11 0c 11 06 8e 69 } //00 00 
	condition:
		any of ($a_*)
 
}