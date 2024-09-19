
rule Trojan_BAT_Taskun_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 08 91 08 11 05 1f 16 5d 91 61 13 09 11 09 07 11 05 17 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_AMAF_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {1f 16 5d 91 13 [0-0f] 61 [0-1e] 17 58 [0-0f] 08 5d 91 13 [0-14] 20 00 01 00 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}