
rule Trojan_BAT_AgentTesla_BSE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BSE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 84 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 09 18 d6 16 2d c2 16 2c 22 26 09 16 2d d0 16 2d cd 08 31 } //1
		$a_02_1 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c 11 07 03 6f ?? ?? ?? 0a 17 da 16 2d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}