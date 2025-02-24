
rule Trojan_BAT_PureLogStealer_MBWQ_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MBWQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 08 1f 14 58 28 ?? 00 00 0a 13 09 07 11 08 1f 10 } //3
		$a_01_1 = {44 68 78 6c 76 47 4e 56 4b 4a 4e 49 34 31 6a 69 6f 54 } //1 DhxlvGNVKJNI41jioT
		$a_01_2 = {65 62 61 46 74 34 59 63 4f 66 59 61 56 45 4a 4e 33 50 } //1 ebaFt4YcOfYaVEJN3P
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}