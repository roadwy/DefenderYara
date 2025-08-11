
rule Trojan_BAT_Taskun_GPPF_MTB{
	meta:
		description = "Trojan:BAT/Taskun.GPPF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 08 61 11 0b 61 13 0c 11 10 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}