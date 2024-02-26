
rule Trojan_BAT_Taskun_AMBD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 07 1f 10 6f 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 08 6f 90 01 01 00 00 0a 06 16 06 8e 69 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}