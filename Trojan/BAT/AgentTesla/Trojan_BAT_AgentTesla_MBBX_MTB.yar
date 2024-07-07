
rule Trojan_BAT_AgentTesla_MBBX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBBX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {24 31 31 66 63 65 61 61 63 2d 61 61 64 64 2d 34 34 62 39 2d 38 30 37 63 2d 32 62 36 34 35 37 33 63 33 39 33 63 } //10 $11fceaac-aadd-44b9-807c-2b64573c393c
		$a_01_1 = {53 74 65 70 73 20 52 65 63 6f 72 64 65 72 } //1 Steps Recorder
		$a_01_2 = {53 6e 61 6b 65 73 41 6e 64 4c 61 64 64 65 72 73 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SnakesAndLadders.Properties.Resources.resources
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {47 65 74 42 79 74 65 73 } //1 GetBytes
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}