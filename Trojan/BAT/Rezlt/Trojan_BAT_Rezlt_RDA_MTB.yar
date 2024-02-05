
rule Trojan_BAT_Rezlt_RDA_MTB{
	meta:
		description = "Trojan:BAT/Rezlt.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 08 93 0d 06 09 04 59 d1 6f 04 00 00 0a 26 08 00 15 17 58 17 58 58 0c } //00 00 
	condition:
		any of ($a_*)
 
}