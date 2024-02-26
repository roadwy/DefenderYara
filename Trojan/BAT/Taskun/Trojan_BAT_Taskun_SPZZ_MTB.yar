
rule Trojan_BAT_Taskun_SPZZ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 00 11 06 17 58 13 06 11 06 } //00 00 
	condition:
		any of ($a_*)
 
}