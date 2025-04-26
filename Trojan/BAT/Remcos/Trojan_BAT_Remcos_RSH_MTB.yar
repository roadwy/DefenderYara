
rule Trojan_BAT_Remcos_RSH_MTB{
	meta:
		description = "Trojan:BAT/Remcos.RSH!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6f 88 00 00 0a 74 30 00 00 01 72 3e 05 00 70 72 42 05 00 70 6f 8c 00 00 0a } //1
		$a_01_1 = {17 00 08 11 05 07 11 05 9a 1f 10 28 8e 00 00 0a 9c 00 11 05 17 58 13 05 11 05 07 8e 69 fe 04 13 06 11 06 2d dc } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}