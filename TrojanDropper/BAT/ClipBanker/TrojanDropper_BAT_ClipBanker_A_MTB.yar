
rule TrojanDropper_BAT_ClipBanker_A_MTB{
	meta:
		description = "TrojanDropper:BAT/ClipBanker.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_03_0 = {0a 16 9a 14 14 6f 90 01 01 00 00 0a 74 90 01 01 00 00 01 0a de 90 00 } //2
		$a_01_1 = {00 00 0a 0b 07 2a } //2
		$a_01_2 = {00 00 04 0b 07 2a } //2
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_5 = {53 65 63 75 72 69 74 79 50 72 6f 74 6f 63 6f 6c } //1 SecurityProtocol
		$a_01_6 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //1 ResourceManager
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}