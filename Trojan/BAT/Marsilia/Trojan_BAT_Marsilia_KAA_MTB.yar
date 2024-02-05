
rule Trojan_BAT_Marsilia_KAA_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {72 01 00 00 70 28 03 00 00 06 72 0d 00 00 70 28 02 00 00 06 0a 28 04 00 00 0a 0b 72 19 00 00 70 28 05 00 00 0a 0c 1f 0a } //00 00 
	condition:
		any of ($a_*)
 
}