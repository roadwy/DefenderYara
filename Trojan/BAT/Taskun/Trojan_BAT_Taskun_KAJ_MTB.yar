
rule Trojan_BAT_Taskun_KAJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 05 1f 16 5d 91 61 13 09 } //00 00 
	condition:
		any of ($a_*)
 
}