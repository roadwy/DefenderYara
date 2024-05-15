
rule Trojan_BAT_Taskun_SPZO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPZO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {5d 91 59 13 90 01 01 07 11 90 01 01 11 90 01 01 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}