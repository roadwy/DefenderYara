
rule Trojan_BAT_Taskun_MBZP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.MBZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5d d4 91 08 11 90 01 01 69 1f 90 01 01 5d 6f 90 01 03 0a 13 90 01 01 11 90 01 01 61 11 90 01 01 59 13 90 01 01 11 90 01 01 20 00 01 00 00 58 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}