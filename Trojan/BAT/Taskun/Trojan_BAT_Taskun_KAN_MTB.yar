
rule Trojan_BAT_Taskun_KAN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 5d d4 91 08 11 90 01 01 d4 91 61 07 11 90 01 01 07 8e 69 6a 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}