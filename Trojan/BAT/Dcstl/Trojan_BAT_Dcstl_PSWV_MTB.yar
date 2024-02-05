
rule Trojan_BAT_Dcstl_PSWV_MTB{
	meta:
		description = "Trojan:BAT/Dcstl.PSWV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {06 02 7d 03 00 00 04 06 15 7d 01 00 00 04 06 7c 02 00 00 04 12 00 28 01 00 00 2b 06 7c 02 00 00 04 28 0d 00 00 0a 2a } //00 00 
	condition:
		any of ($a_*)
 
}