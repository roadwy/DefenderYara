
rule Trojan_BAT_AgentTesla_AMCB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 72 01 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 00 00 0a 72 01 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_AMCB_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 00 41 00 30 00 44 00 32 00 42 00 39 00 38 00 31 00 39 00 32 00 42 00 46 00 41 00 31 00 34 00 30 00 42 00 31 00 43 00 30 00 44 00 32 00 42 00 38 00 46 00 30 00 32 00 38 00 43 00 30 00 42 00 7c 00 7c 00 31 00 42 00 32 00 38 00 34 00 32 00 7c 00 7c 00 } //2 1A0D2B98192BFA140B1C0D2B8F028C0B||1B2842||
		$a_80_1 = {55 44 46 5f 55 74 69 6c 69 74 79 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //UDF_Utility.Properties.Resources  2
		$a_80_2 = {48 65 78 53 74 72 69 6e 67 54 6f 42 79 74 65 41 72 72 61 79 } //HexStringToByteArray  1
	condition:
		((#a_01_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1) >=5
 
}