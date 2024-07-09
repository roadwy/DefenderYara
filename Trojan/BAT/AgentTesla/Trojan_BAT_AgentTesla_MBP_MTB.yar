
rule Trojan_BAT_AgentTesla_MBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b6 00 b6 00 60 00 6c 25 71 00 51 00 88 25 88 25 88 25 88 25 4d 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 45 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 2f 00 2f 00 38 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_MBP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 68 2b 69 08 06 8e 69 5d 91 7e ?? 00 00 04 08 91 61 d2 6f ?? 00 00 0a 08 17 58 0c 08 16 2d b4 } //1
		$a_01_1 = {34 38 35 66 61 36 62 35 2d 37 33 39 31 2d 34 64 37 34 2d 38 36 35 36 2d 33 33 64 39 66 31 34 66 61 66 38 38 } //1 485fa6b5-7391-4d74-8656-33d9f14faf88
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}