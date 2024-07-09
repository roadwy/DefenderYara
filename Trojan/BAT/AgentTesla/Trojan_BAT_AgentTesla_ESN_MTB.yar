
rule Trojan_BAT_AgentTesla_ESN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ESN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 02 11 06 91 08 18 d6 18 da 61 07 11 07 19 d6 19 da 91 61 b4 9c 11 07 } //1
		$a_03_1 = {2b 6e 02 09 28 ?? ?? ?? 06 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_ESN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ESN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {11 00 03 05 1f 16 5d 7e ?? ?? ?? 04 28 ?? ?? ?? 06 61 13 01 } //1
		$a_03_1 = {03 02 20 00 22 00 00 04 7e ?? ?? ?? 04 28 ?? ?? ?? 06 03 04 17 58 20 00 22 00 00 5d } //1
		$a_01_2 = {24 33 64 36 64 37 36 65 63 2d 34 30 37 66 2d 34 37 66 66 2d 39 31 62 65 2d 63 64 63 35 62 37 32 38 64 35 38 33 } //1 $3d6d76ec-407f-47ff-91be-cdc5b728d583
		$a_01_3 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_4 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}