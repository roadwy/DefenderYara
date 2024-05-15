
rule Trojan_BAT_DarkTortilla_RDD_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.RDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {07 28 a3 00 00 06 0d 09 28 a4 00 00 06 13 04 11 04 08 6f b6 00 00 0a 00 08 0a } //00 00 
	condition:
		any of ($a_*)
 
}