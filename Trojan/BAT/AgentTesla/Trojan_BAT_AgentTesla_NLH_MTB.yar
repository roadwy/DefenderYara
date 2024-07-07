
rule Trojan_BAT_AgentTesla_NLH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {f2 02 f4 02 0f 03 ef 02 0c 20 0c 06 eb 02 0c 20 0c 06 0c 20 0c 06 e3 02 0c 20 0c 06 0c 20 0c 06 cd 02 cd 02 d6 02 0c 20 0c 06 ea 02 05 03 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 df 02 } //1
		$a_01_1 = {d6 02 f0 02 e0 02 e0 02 02 03 f7 02 e3 02 15 03 ef 02 f0 02 e1 02 16 03 d7 02 d6 02 09 03 17 03 e0 02 01 03 d2 02 15 03 0c 20 0c 06 f5 02 f0 02 eb 02 e8 02 ed 02 ea 02 04 03 c9 02 cd 02 cd 02 d6 02 f0 02 e0 02 df 02 e9 02 ed 02 ff 02 f0 02 02 03 f8 } //1
		$a_01_2 = {06 e1 02 f2 02 f5 02 e1 02 e1 02 d1 02 0c 20 0c 06 0c 20 0c 06 f6 02 d3 02 cf 02 06 03 e6 02 d1 02 d7 02 f8 02 e0 02 0b 03 e4 02 e4 02 df 02 ef 02 0c 20 0c 06 0c 20 0c 06 05 03 0c 20 0c 06 0c 20 0c 06 f8 02 e3 02 15 03 f3 02 d2 02 00 03 ee 02 cd 02 } //1
		$a_01_3 = {eb 02 df 02 e8 02 ef 02 ef 02 e7 02 df 02 15 03 09 03 0c 20 0c 06 0c 20 0c 06 e0 02 df 02 e3 02 05 03 e0 02 0c 20 0c 06 df 02 e0 02 df 02 e6 02 e7 02 e0 } //1
		$a_01_4 = {df 02 e7 02 e3 02 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c 06 0c 20 0c } //1
		$a_01_5 = {43 53 50 5f 54 69 63 6b 65 74 69 6e 67 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 CSP_Ticketing.Resources.resources
		$a_80_6 = {46 72 6f 6d 42 61 73 65 36 34 } //FromBase64  1
		$a_01_7 = {52 65 70 6c 61 63 65 } //1 Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_80_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}