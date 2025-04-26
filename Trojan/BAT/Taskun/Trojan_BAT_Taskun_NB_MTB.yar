
rule Trojan_BAT_Taskun_NB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5d 59 d2 9c 06 17 58 0a 06 20 00 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}