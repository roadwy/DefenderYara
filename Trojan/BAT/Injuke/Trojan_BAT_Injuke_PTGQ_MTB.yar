
rule Trojan_BAT_Injuke_PTGQ_MTB{
	meta:
		description = "Trojan:BAT/Injuke.PTGQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2b f6 09 28 90 01 01 00 00 0a 28 90 01 01 01 00 06 74 0a 00 00 1b 0a 06 75 0a 00 00 1b 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}