
rule Trojan_BAT_AgentTesla_IKIN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.IKIN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,34 00 34 00 07 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4d 65 74 68 6f 64 } //10 GetMethod
		$a_01_1 = {47 65 74 54 79 70 65 } //10 GetType
		$a_01_2 = {52 65 76 65 72 73 65 } //10 Reverse
		$a_01_3 = {49 6e 76 6f 6b 65 } //10 Invoke
		$a_01_4 = {54 6f 41 72 72 61 79 } //10 ToArray
		$a_80_5 = {65 63 32 2d 35 34 2d 31 36 33 2d 31 37 31 2d 31 38 39 2e 63 6f 6d 70 75 74 65 2d 31 2e 61 6d 61 7a 6f 6e 61 77 73 2e 63 6f 6d 2f 66 69 6c 65 2f 4b 65 66 70 61 62 7a 2e 70 6e 67 } //ec2-54-163-171-189.compute-1.amazonaws.com/file/Kefpabz.png  2
		$a_80_6 = {74 72 61 6e 73 66 65 72 2e 73 68 2f 67 65 74 2f 4d 69 54 6f 46 43 2f 50 62 72 64 65 68 6d 2e 6c 6f 67 } //transfer.sh/get/MiToFC/Pbrdehm.log  2
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=52
 
}