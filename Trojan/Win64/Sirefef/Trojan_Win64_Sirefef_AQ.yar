
rule Trojan_Win64_Sirefef_AQ{
	meta:
		description = "Trojan:Win64/Sirefef.AQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {38 30 30 30 30 30 63 62 2e 40 } //1 800000cb.@
		$a_01_1 = {c7 44 24 28 40 00 00 00 66 89 44 24 68 c7 44 24 60 02 00 10 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}