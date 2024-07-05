
rule Trojan_BAT_Taskun_KAS_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 6a 5d d4 91 58 07 06 95 58 20 ff 00 00 00 5f 0c 07 06 } //00 00 
	condition:
		any of ($a_*)
 
}