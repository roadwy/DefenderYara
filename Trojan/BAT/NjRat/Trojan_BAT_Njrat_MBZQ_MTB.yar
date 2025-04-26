
rule Trojan_BAT_Njrat_MBZQ_MTB{
	meta:
		description = "Trojan:BAT/Njrat.MBZQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {54 00 56 00 71 00 51 00 26 00 26 00 4d 00 26 00 26 00 26 00 26 00 45 00 26 00 26 00 26 00 26 00 2f 00 2f 00 38 00 26 00 26 00 4c 00 67 00 } //1 TVqQ&&M&&&&E&&&&//8&&Lg
		$a_01_1 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 } //1 EntryPoint
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}