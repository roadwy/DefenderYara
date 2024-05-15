
rule Trojan_BAT_Taskun_KAO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {07 08 91 11 90 01 01 08 1f 90 01 01 5d 91 61 07 11 90 01 01 91 59 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}