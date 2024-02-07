
rule Trojan_BAT_Remcos_AGRT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.AGRT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 8e 69 5d 91 7e 90 01 03 04 11 01 91 61 d2 6f 90 00 } //01 00 
		$a_01_1 = {54 6f 41 72 72 61 79 } //00 00  ToArray
	condition:
		any of ($a_*)
 
}