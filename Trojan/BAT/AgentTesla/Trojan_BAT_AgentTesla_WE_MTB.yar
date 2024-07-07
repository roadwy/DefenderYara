
rule Trojan_BAT_AgentTesla_WE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.WE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {06 02 07 6f 90 01 04 03 07 03 6f 90 01 04 5d 6f 90 01 04 61 d1 6f 90 01 04 26 07 17 58 0b 07 02 6f 90 01 04 32 d5 90 00 } //10
		$a_80_1 = {53 74 72 69 6e 67 44 65 63 72 79 70 74 } //StringDecrypt  1
		$a_80_2 = {46 72 6f 6d 42 61 73 65 36 34 43 68 61 72 41 72 72 61 79 } //FromBase64CharArray  1
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}