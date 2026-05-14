
rule Trojan_BAT_Agent_G_AMTB{
	meta:
		description = "Trojan:BAT/Agent.G!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_80_0 = {36 35 2e 31 30 39 2e 31 31 35 2e 32 35 } //65.109.115.25  3
	condition:
		((#a_80_0  & 1)*3) >=3
 
}