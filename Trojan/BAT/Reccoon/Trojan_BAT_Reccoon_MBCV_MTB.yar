
rule Trojan_BAT_Reccoon_MBCV_MTB{
	meta:
		description = "Trojan:BAT/Reccoon.MBCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {2b 02 26 16 2b 02 26 16 00 00 00 00 00 20 10 22 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}