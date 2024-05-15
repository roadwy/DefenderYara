
rule Trojan_BAT_Marsilia_KAE_MTB{
	meta:
		description = "Trojan:BAT/Marsilia.KAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {07 08 02 08 93 06 08 06 8e 69 5d 93 61 d1 9d 08 17 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}