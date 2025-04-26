
rule Backdoor_BAT_Bladabindi_MX_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {17 9a 0a 06 14 18 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 72 95 01 00 70 a2 6f ?? ?? ?? ?? 26 2a } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}