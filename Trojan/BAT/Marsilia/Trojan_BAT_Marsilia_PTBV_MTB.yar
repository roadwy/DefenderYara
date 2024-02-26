
rule Trojan_BAT_Marsilia_PTBV_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.PTBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 0c 28 90 01 01 00 00 0a 11 0d 28 90 01 01 00 00 0a 6f 24 00 00 0a a2 2b 06 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}