
rule Trojan_BAT_Taskun_SPPO_MTB{
	meta:
		description = "Trojan:BAT/Taskun.SPPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}