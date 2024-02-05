
rule Trojan_BAT_Darkcomet_AXM_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.AXM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {16 02 8e b7 17 59 0c 0b 2b 0f 02 07 02 07 91 1f 0d 61 d2 9c 07 1f 0d 58 0b 07 08 31 ed } //00 00 
	condition:
		any of ($a_*)
 
}