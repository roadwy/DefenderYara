
rule Trojan_BAT_Bladabindi_ABAA_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ABAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {fe 0c 01 00 fe 0c 02 00 8f ?? 00 00 01 25 47 fe 0c 01 00 fe 0c 07 00 91 fe 0c 00 00 20 ?? 00 00 00 58 4a 61 d2 61 d2 52 20 ?? 00 00 00 fe 0e 0a 00 } //1
		$a_01_1 = {00 fe 0c 05 00 fe 0c 00 00 20 08 00 00 00 58 fe 0c 01 00 8e 69 fe 17 20 0b 00 00 00 fe 0e 0a 00 } //1
		$a_01_2 = {fe 0c 00 00 fe 09 00 00 fe 0c 00 00 4a 61 58 fe 0e 00 00 20 07 00 00 00 fe 0e 0a 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}