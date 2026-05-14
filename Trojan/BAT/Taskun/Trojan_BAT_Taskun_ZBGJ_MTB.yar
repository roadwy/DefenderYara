
rule Trojan_BAT_Taskun_ZBGJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZBGJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 13 28 11 28 1f 0b 58 1d 11 23 58 61 d2 13 1d 11 20 16 91 11 20 18 91 1e 62 60 11 1d 19 62 58 13 1e 16 13 1b } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}