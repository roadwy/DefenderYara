
rule Trojan_BAT_Taskun_MBFQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 13 0d 28 90 01 04 14 20 90 01 04 28 90 01 04 17 8d 90 01 04 25 16 11 90 01 01 28 90 01 04 a2 14 14 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_Taskun_MBFQ_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.MBFQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {06 1f 16 5d 91 13 90 01 01 11 90 01 01 11 90 01 01 61 13 90 01 01 11 90 01 01 11 90 01 01 59 13 90 00 } //01 00 
		$a_03_1 = {07 06 8e 69 5d 06 07 06 8e 69 5d 91 08 07 08 6f 90 01 01 00 00 0a 5d 6f 90 01 01 00 00 0a 61 28 90 01 01 00 00 0a 06 07 17 58 06 8e 69 5d 91 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}