
rule Trojan_BAT_AgentTesla_MBEI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 37 66 65 39 30 31 63 66 2d 33 31 34 64 2d 34 32 63 36 2d 61 37 38 66 2d 38 36 61 32 37 64 64 35 35 36 65 63 } //1 $7fe901cf-314d-42c6-a78f-86a27dd556ec
		$a_01_1 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_MBEI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 13 08 11 04 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 11 04 28 ?? 00 00 06 13 0c 02 11 0a 11 0b 11 0c } //1
		$a_01_1 = {45 00 37 00 51 00 43 00 59 00 37 00 34 00 43 00 46 00 38 00 38 00 34 00 41 00 5a 00 44 00 34 00 41 00 38 00 5a 00 39 00 53 00 35 00 } //1 E7QCY74CF884AZD4A8Z9S5
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}