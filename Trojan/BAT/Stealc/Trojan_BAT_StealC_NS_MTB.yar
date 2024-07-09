
rule Trojan_BAT_StealC_NS_MTB{
	meta:
		description = "Trojan:BAT/StealC.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 37 00 00 01 25 d0 36 00 00 04 28 ?? 00 00 0a 6f d6 00 00 0a } //3
		$a_03_1 = {07 1f 10 8d 37 00 00 01 25 d0 37 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f d8 00 00 0a } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}