
rule Trojan_BAT_Taskun_AMBE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8e 69 6a 5d d4 91 61 90 01 0e 6a 5d d4 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_AMBE_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5d 91 61 06 07 17 58 09 5d 91 59 20 00 01 00 00 58 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_AMBE_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.AMBE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {07 11 05 07 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 11 90 01 01 61 13 90 01 01 07 11 90 01 01 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}