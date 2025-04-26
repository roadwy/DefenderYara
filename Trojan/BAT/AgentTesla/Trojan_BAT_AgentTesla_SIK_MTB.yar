
rule Trojan_BAT_AgentTesla_SIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 11 04 11 05 6f 3e 00 00 0a 13 06 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 08 6f 41 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 08 6f 41 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 11 05 17 58 13 05 11 05 07 6f 44 00 00 0a 32 a3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_SIK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 00 1e 01 00 0d 16 13 06 2b 77 00 16 13 07 2b 5a 00 07 11 06 11 07 6f af 00 00 0a 13 08 08 6f b0 00 00 0a 19 58 09 fe 02 16 fe 01 13 09 11 09 2c 0d } //1
		$a_00_1 = {00 00 2b 25 00 09 08 6f b0 00 00 0a 59 13 0a 11 0a 16 fe 02 13 0b 11 0b 2c 0d 00 08 11 08 11 0a 28 63 00 00 06 00 00 2b 17 00 11 07 17 58 13 07 11 07 07 6f b1 00 00 0a fe 04 13 0c 11 0c 2d 96 } //1
		$a_01_2 = {4d 69 6e 65 53 77 65 65 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 MineSweeper.Properties.Resources.resources
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_SIK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_03_0 = {1f 16 13 04 20 00 01 00 00 13 05 09 20 00 56 00 00 5d 13 06 07 11 06 91 08 09 11 04 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 13 07 07 09 19 58 18 59 20 00 56 00 00 5d 91 28 ?? ?? ?? 0a 13 08 11 07 11 08 59 6e 11 05 6a 58 13 09 07 11 06 11 09 11 05 6a 5d 1f 19 6a 58 1f 19 6a 59 d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 0a 11 0a } //10
		$a_81_1 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_2 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_01_3 = {48 00 65 00 61 00 76 00 79 00 44 00 75 00 63 00 6b 00 } //1 HeavyDuck
		$a_01_4 = {37 00 39 00 35 00 48 00 43 00 38 00 43 00 4a 00 31 00 51 00 46 00 31 00 42 00 54 00 32 00 34 00 48 00 47 00 57 00 48 00 35 00 35 00 } //1 795HC8CJ1QF1BT24HGWH55
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}
rule Trojan_BAT_AgentTesla_SIK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 11 0c 17 6a 58 11 08 6a 5d d4 91 13 0d 11 0d 13 0e 07 11 0c 11 08 6a 5d d4 91 13 0f 08 11 0c 69 1f 16 5d 6f 28 00 00 0a 13 10 11 0f 11 10 61 13 11 11 11 11 0e 59 13 12 11 12 20 00 01 00 00 58 20 ff 00 00 00 5f 13 12 07 11 0c 11 08 6a 5d d4 11 12 28 29 00 00 0a 9c 00 11 0c 17 6a 58 13 0c 11 0c 11 08 17 59 6a fe 02 16 fe 01 13 13 11 13 2d 8c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}