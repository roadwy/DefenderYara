
rule Trojan_BAT_AgentTesla_AN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {16 9a 20 08 12 00 00 95 e0 95 7e 2e 00 00 04 16 9a 20 33 03 00 00 95 61 7e 2e 00 00 04 16 9a 20 ef 0d 00 00 95 2e 03 17 2b 01 16 58 } //2
		$a_01_1 = {95 2e 03 16 2b 01 17 17 59 7e 2e 00 00 04 16 9a 20 12 03 00 00 95 5f 7e 2e 00 00 04 16 9a 20 f8 0f 00 00 95 61 58 80 35 00 00 04 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {01 57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 2a } //1
		$a_01_1 = {53 74 6f 70 77 61 74 63 68 } //1 Stopwatch
		$a_01_2 = {73 65 74 5f 53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //1 set_SecurityProtocol
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_00_4 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //1 discordapp.com/attachments
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}