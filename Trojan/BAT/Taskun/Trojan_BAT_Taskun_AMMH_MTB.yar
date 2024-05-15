
rule Trojan_BAT_Taskun_AMMH_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {5d 91 61 07 11 90 02 05 91 59 20 00 01 00 00 58 d2 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_AMMH_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 02 32 1f 16 5d 91 61 07 11 90 01 01 91 59 20 00 01 00 00 58 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}