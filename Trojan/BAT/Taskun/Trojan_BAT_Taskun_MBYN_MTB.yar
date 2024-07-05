
rule Trojan_BAT_Taskun_MBYN_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBYN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {d4 11 0e 6e 11 11 20 ff 00 00 00 5f 6a 61 d2 9c 11 04 17 6a 58 13 04 } //00 00 
	condition:
		any of ($a_*)
 
}