
rule Trojan_BAT_Donut_MK_MTB{
	meta:
		description = "Trojan:BAT/Donut.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 00 70 7e 2e 00 00 04 28 25 00 00 0a 7e 34 00 00 04 7e 2e 00 00 04 28 25 00 00 0a 28 08 00 00 06 2c 09 02 17 } //20
		$a_03_1 = {02 7b 35 00 00 04 72 ?? 12 00 70 28 25 00 00 0a 6f ca 00 00 0a 02 7b 38 00 00 04 6f c9 00 00 0a 02 7b 35 00 00 04 6f cb 00 00 0a } //15
	condition:
		((#a_01_0  & 1)*20+(#a_03_1  & 1)*15) >=35
 
}