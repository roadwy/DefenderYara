
rule Trojan_BAT_Lazy_PTFP_MTB{
	meta:
		description = "Trojan:BAT/Lazy.PTFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {73 37 00 00 0a 25 80 4b 00 00 04 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 10 01 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}