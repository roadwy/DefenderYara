
rule Trojan_BAT_Taskun_AMAE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 07 11 90 01 01 91 11 90 01 01 61 13 90 01 01 07 11 90 01 01 91 13 90 01 01 02 11 90 01 01 11 90 01 01 59 28 90 01 04 13 0a 07 11 90 01 01 11 90 01 01 28 90 01 04 9c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}