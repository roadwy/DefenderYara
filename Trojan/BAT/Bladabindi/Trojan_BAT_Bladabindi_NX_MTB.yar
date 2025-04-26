
rule Trojan_BAT_Bladabindi_NX_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 09 16 6f ?? ?? ?? 0a 13 04 12 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 d6 0d 09 08 31 dc } //1
		$a_81_1 = {61 2e 74 6f 70 34 74 6f 70 2e 69 6f 2f 70 5f 32 34 32 38 6d 6e 36 39 } //1 a.top4top.io/p_2428mn69
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}