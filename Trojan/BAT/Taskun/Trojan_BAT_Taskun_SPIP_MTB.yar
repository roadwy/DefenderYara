
rule Trojan_BAT_Taskun_SPIP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {91 61 07 08 17 6a 58 07 8e 69 6a 5d d4 91 28 90 01 03 0a 59 11 0a 58 11 0a 5d 28 90 01 03 0a 9c 08 17 6a 58 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}