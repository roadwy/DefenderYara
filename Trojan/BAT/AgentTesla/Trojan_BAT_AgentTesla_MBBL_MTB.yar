
rule Trojan_BAT_AgentTesla_MBBL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? ?? ?? 0a 05 03 17 58 05 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
		$a_01_1 = {48 00 49 00 47 00 38 00 34 00 34 00 34 00 48 00 5a 00 41 00 30 00 38 00 37 00 38 00 4f 00 35 00 39 00 5a 00 5a 00 37 00 47 00 46 00 } //1 HIG8444HZA0878O59ZZ7GF
		$a_01_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 } //1 System.Reflection.Assembly
		$a_01_3 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65 00 } //1 CreateInstance
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}