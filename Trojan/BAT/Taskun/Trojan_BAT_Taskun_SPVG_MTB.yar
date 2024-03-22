
rule Trojan_BAT_Taskun_SPVG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPVG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 91 61 13 08 11 08 07 09 17 58 08 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 13 09 } //00 00 
	condition:
		any of ($a_*)
 
}