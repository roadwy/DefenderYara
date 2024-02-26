
rule Trojan_BAT_Taskun_KAG_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 91 13 0e 11 0d 11 0e 61 13 0f 07 11 0a 11 0f 11 0c 59 } //00 00 
	condition:
		any of ($a_*)
 
}