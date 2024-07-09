
rule Trojan_BAT_Zusy_NS_MTB{
	meta:
		description = "Trojan:BAT/Zusy.NS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 1f 10 5a 13 04 1f 10 8d ?? 00 00 01 13 05 03 11 04 11 05 16 1f 10 28 ?? 00 00 0a 06 11 05 16 11 05 8e 69 6f ?? 00 00 0a 16 08 09 1f 10 5a 1f 10 } //5
		$a_01_1 = {44 50 41 70 70 2e 63 6f 6d } //1 DPApp.com
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}