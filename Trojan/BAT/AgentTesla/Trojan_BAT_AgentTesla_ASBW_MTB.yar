
rule Trojan_BAT_AgentTesla_ASBW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {11 03 11 04 11 08 58 17 58 17 59 11 07 11 09 58 17 58 17 59 6f 90 01 01 00 00 0a 13 0a 20 02 00 00 00 38 90 00 } //2
		$a_03_1 = {11 02 11 01 11 0b 9c 38 90 01 02 ff ff 02 7b 90 00 } //1
		$a_81_2 = {52 65 73 6f 75 72 63 65 46 61 69 6c 75 72 65 4d 6f 64 65 6c 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //1 ResourceFailureModel.Properties.Resources
		$a_01_3 = {47 65 74 50 69 78 65 6c } //1 GetPixel
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}