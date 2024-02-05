
rule Trojan_BAT_AsyncRAT_I_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {02 03 5d 0c 08 8c } //02 00 
		$a_01_1 = {04 05 60 04 66 05 } //02 00 
		$a_01_2 = {66 60 5f 8c } //00 00 
	condition:
		any of ($a_*)
 
}