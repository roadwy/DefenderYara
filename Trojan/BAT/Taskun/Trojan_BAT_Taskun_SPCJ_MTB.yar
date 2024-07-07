
rule Trojan_BAT_Taskun_SPCJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0b 91 61 07 11 09 91 11 06 58 11 06 5d 59 d2 9c 00 11 05 17 58 13 05 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}