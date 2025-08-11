
rule Trojan_BAT_Taskun_WQ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.WQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 69 00 00 01 11 05 11 0a 75 48 00 00 1b 11 0c 11 07 58 11 09 59 93 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}