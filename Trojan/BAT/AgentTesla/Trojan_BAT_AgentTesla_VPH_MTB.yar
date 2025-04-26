
rule Trojan_BAT_AgentTesla_VPH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.VPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {7e 11 00 00 04 73 be 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 0f 00 00 1b 0a 06 28 ?? ?? ?? 06 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 4d 00 00 01 6f ?? ?? ?? 0a 1a 9a 80 10 00 00 04 23 d1 37 b7 3b 43 62 20 40 } //1
		$a_01_1 = {4b 61 6c 63 69 75 6d } //1 Kalcium
		$a_01_2 = {49 00 4b 00 4d 00 4e 00 4a 00 55 00 48 00 42 00 56 00 47 00 59 00 54 00 46 00 43 00 58 00 44 00 52 00 45 00 53 00 5a 00 41 00 57 00 51 00 } //1 IKMNJUHBVGYTFCXDRESZAWQ
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}