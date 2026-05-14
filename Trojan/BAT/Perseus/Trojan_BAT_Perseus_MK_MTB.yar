
rule Trojan_BAT_Perseus_MK_MTB{
	meta:
		description = "Trojan:BAT/Perseus.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,37 00 37 00 05 00 00 "
		
	strings :
		$a_81_0 = {43 50 55 5a 31 34 31 2e 73 79 73 20 66 61 69 6c 65 64 20 74 6f 20 6c 6f 61 64 } //15 CPUZ141.sys failed to load
		$a_81_1 = {44 61 6e 6b 49 6e 6a 65 63 74 69 6f 6e 46 6f 72 6d } //15 DankInjectionForm
		$a_81_2 = {49 6e 6a 65 63 74 69 6e 67 20 28 52 41 57 29 20 2d 3e 20 7b 30 7d 2f 7b 31 7d } //10 Injecting (RAW) -> {0}/{1}
		$a_81_3 = {48 69 6a 61 63 6b 20 54 68 72 65 61 64 } //10 Hijack Thread
		$a_81_4 = {63 6f 6d 62 6f 49 6e 6a 65 63 74 69 6f 6e 4d 65 74 68 6f 64 } //5 comboInjectionMethod
	condition:
		((#a_81_0  & 1)*15+(#a_81_1  & 1)*15+(#a_81_2  & 1)*10+(#a_81_3  & 1)*10+(#a_81_4  & 1)*5) >=55
 
}