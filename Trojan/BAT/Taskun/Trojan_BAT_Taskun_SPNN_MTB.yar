
rule Trojan_BAT_Taskun_SPNN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 91 61 07 11 06 91 59 20 00 01 00 00 58 13 07 1f 0b } //00 00 
	condition:
		any of ($a_*)
 
}