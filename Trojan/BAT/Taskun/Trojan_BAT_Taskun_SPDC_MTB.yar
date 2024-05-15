
rule Trojan_BAT_Taskun_SPDC_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {d4 91 61 28 90 01 03 0a 07 11 90 01 01 08 6a 5d d4 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}