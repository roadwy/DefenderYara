
rule Trojan_BAT_AgentTesla_ABY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {17 9a 20 90 04 00 00 95 6e 31 03 16 2b 01 17 17 59 7e 08 00 00 04 17 9a 20 93 0e 00 00 95 5f 7e 08 00 00 04 17 9a 20 12 0a 00 00 95 61 58 81 06 00 00 01 } //2
		$a_01_1 = {20 b4 0b 00 00 95 2e 03 16 2b 01 17 17 59 7e 02 00 00 04 20 63 09 00 00 95 5f 7e 02 00 00 04 20 02 0b 00 00 95 61 58 81 07 00 00 01 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_ABY_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {35 00 41 00 34 00 41 00 34 00 42 00 36 00 43 00 00 0d 36 00 38 00 37 00 36 00 36 00 39 00 00 13 59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 } //1
		$a_01_1 = {49 5a 48 73 2e 67 2e 72 65 73 6f 75 72 63 65 73 } //1 IZHs.g.resources
		$a_01_2 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 } //1 aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources
		$a_01_3 = {59 00 35 00 74 00 46 00 76 00 55 00 38 00 45 00 59 00 } //1 Y5tFvU8EY
		$a_01_4 = {44 00 61 00 76 00 69 00 73 00 31 00 31 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Davis11.Properties.Resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}