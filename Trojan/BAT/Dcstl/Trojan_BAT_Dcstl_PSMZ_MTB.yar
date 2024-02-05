
rule Trojan_BAT_Dcstl_PSMZ_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8e 69 28 1f 00 00 0a 07 2a 28 0b 00 00 06 2b ce 0a 2b cd 28 20 00 00 0a 2b ce 06 2b cd 6f 21 00 00 0a 2b c8 28 05 00 00 06 2b c3 } //00 00 
	condition:
		any of ($a_*)
 
}