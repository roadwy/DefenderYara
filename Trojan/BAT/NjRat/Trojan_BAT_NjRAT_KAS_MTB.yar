
rule Trojan_BAT_NjRAT_KAS_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1e 5d 0c 02 07 8f 90 01 01 00 00 01 25 71 90 01 01 00 00 01 06 d2 61 d2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}