
rule Trojan_BAT_Convagent_MX_MTB{
	meta:
		description = "Trojan:BAT/Convagent.MX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 1f 01 00 70 07 72 cc 01 00 70 28 05 00 00 0a 28 03 00 00 06 00 72 e8 01 00 70 07 72 95 02 00 70 28 05 00 00 0a 28 03 00 00 06 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}