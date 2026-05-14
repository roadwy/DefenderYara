
rule Trojan_BAT_SpyAgent_B_AMTB{
	meta:
		description = "Trojan:BAT/SpyAgent.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_80_0 = {61 70 69 6b 6f 6b 6f 61 70 69 2e 63 6f 6d } //apikokoapi.com  3
		$a_80_1 = {37 37 2e 31 30 35 2e 31 36 36 2e 32 32 39 } //77.105.166.229  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3) >=6
 
}