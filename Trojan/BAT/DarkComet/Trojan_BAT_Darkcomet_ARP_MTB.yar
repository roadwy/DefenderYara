
rule Trojan_BAT_Darkcomet_ARP_MTB{
	meta:
		description = "Trojan:BAT/Darkcomet.ARP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 09 02 09 91 06 09 06 8e 69 5d 91 08 58 20 ff 00 00 00 5f 61 d2 9c 09 17 58 0d 09 07 8e 69 17 } //00 00 
	condition:
		any of ($a_*)
 
}