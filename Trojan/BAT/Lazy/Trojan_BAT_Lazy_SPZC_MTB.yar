
rule Trojan_BAT_Lazy_SPZC_MTB{
	meta:
		description = "Trojan:BAT/Lazy.SPZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {58 08 5d 13 0f 11 1a 20 02 01 00 00 94 20 78 92 00 00 59 13 18 } //02 00 
		$a_01_1 = {07 11 0a 91 11 0e 61 07 11 0f 91 59 13 10 11 19 1f 28 93 20 f2 59 00 00 59 13 18 } //00 00 
	condition:
		any of ($a_*)
 
}