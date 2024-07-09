
rule Trojan_BAT_AgentTesla_BKB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } //1
		$a_02_1 = {02 02 8e 69 17 da 91 1f 70 61 0c 02 8e 69 17 d6 17 da 17 d6 8d ?? ?? ?? 01 0d 16 28 } //1
		$a_02_2 = {07 02 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 06 84 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 26 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}