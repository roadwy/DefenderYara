
rule Trojan_BAT_Taskun_AMMF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 91 13 90 02 1e 59 20 00 01 00 00 58 d2 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_AMMF_MTB_2{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 02 07 11 90 01 01 91 11 90 01 01 61 07 11 90 01 01 91 20 ff 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_Taskun_AMMF_MTB_3{
	meta:
		description = "Trojan:BAT/Taskun.AMMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 58 08 5d 13 90 01 01 07 11 90 01 01 91 11 90 01 01 61 13 90 01 01 07 11 90 01 01 91 13 90 01 01 02 11 90 01 01 11 90 01 01 28 90 01 04 13 90 01 01 07 11 90 01 01 11 90 01 01 28 90 01 01 00 00 0a d2 9c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}