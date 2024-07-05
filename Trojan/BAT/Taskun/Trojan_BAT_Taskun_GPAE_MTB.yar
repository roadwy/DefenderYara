
rule Trojan_BAT_Taskun_GPAE_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GPAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {61 13 11 11 07 11 0c d4 11 11 20 ff 00 00 00 5f d2 9c } //00 00 
	condition:
		any of ($a_*)
 
}