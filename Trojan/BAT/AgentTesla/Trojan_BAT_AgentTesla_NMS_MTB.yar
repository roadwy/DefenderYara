
rule Trojan_BAT_AgentTesla_NMS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {4c 74 77 62 64 6a 77 6a 6a 75 7a 78 75 66 61 2e 4b 6e 6a 65 63 75 6e } //Ltwbdjwjjuzxufa.Knjecun  10
		$a_80_1 = {58 68 66 71 64 64 67 63 6c 6d 71 79 72 75 79 6d 77 74 6e 63 67 78 2e 4c 6f 70 6a 79 71 66 } //Xhfqddgclmqyruymwtncgx.Lopjyqf  10
		$a_80_2 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 } //cdn.discordapp.com/attachments/9  1
		$a_01_3 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_4 = {44 72 61 6d 61 } //1 Drama
		$a_01_5 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_01_7 = {52 65 61 64 42 79 74 65 73 } //1 ReadBytes
	condition:
		((#a_80_0  & 1)*10+(#a_80_1  & 1)*10+(#a_80_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=16
 
}