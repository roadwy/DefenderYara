
rule Trojan_BAT_AgentTesla_EVH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EVH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_01_0 = {00 49 52 65 73 6f 75 72 63 65 57 72 69 74 65 72 00 } //1
		$a_01_1 = {00 70 61 73 73 00 74 74 00 69 00 } //1
		$a_01_2 = {00 44 65 62 75 67 56 69 65 77 00 } //1
		$a_01_3 = {00 4d 73 63 6f 72 6c 69 62 00 } //1 䴀捳牯楬b
		$a_01_4 = {00 4b 65 79 65 64 43 6f 6c 6c 65 63 74 69 6f 6e 00 4f 50 54 53 00 } //1 䬀祥摥潃汬捥楴湯伀呐S
		$a_01_5 = {00 50 69 6e 6e 61 62 6c 65 42 75 66 66 65 72 00 } //1 倀湩慮汢䉥晵敦r
		$a_01_6 = {00 47 65 74 54 79 70 65 00 } //1
		$a_01_7 = {00 43 6f 64 65 50 61 67 65 00 } //1 䌀摯健条e
		$a_01_8 = {00 44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 00 } //1 䐀扥杵楧杮潍敤s
		$a_01_9 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=10
 
}