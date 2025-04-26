
rule Trojan_BAT_AgentTesla_PSBM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PSBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_03_0 = {7e be 00 00 04 14 fe 03 0d 09 2c 37 7e be 00 00 04 d0 08 00 00 1b 28 24 ?? ?? ?? 6f f3 ?? ?? ?? 13 04 11 04 2c 1b 20 cd b3 7d fb 28 d0 01 00 06 16 8d 7b 00 00 01 28 f4 ?? ?? ?? 73 f5 ?? ?? ?? 7a 2b 0a 73 f6 ?? ?? ?? 80 be 00 00 04 7e be 00 00 04 d0 08 00 00 1b 28 24 ?? ?? ?? 14 6f f7 ?? ?? ?? 28 01 00 00 2b 0b de 70 } //5
		$a_01_1 = {47 65 74 48 61 73 68 43 6f 64 65 } //1 GetHashCode
		$a_01_2 = {43 6f 6e 74 61 69 6e 73 4b 65 79 } //1 ContainsKey
		$a_01_3 = {47 65 74 52 65 73 6f 75 72 63 65 53 74 72 69 6e 67 } //1 GetResourceString
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}