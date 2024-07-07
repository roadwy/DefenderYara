
rule Trojan_BAT_AgentTesla_NQK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NQK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_81_0 = {58 6c 6b 73 79 75 78 74 63 76 62 71 77 6e 62 2e 42 76 66 63 78 72 63 69 79 6b 61 6b 76 78 61 6e 78 73 62 66 74 6b 6a } //10 Xlksyuxtcvbqwnb.Bvfcxrciykakvxanxsbftkj
		$a_81_1 = {48 70 72 61 6e 78 2e 4d 74 6c 78 63 6c 6b 68 73 65 69 72 67 77 6e 65 } //10 Hpranx.Mtlxclkhseirgwne
		$a_01_2 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_3 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_4 = {63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 } //1 cdn.discordapp.com/attachments/9
	condition:
		((#a_81_0  & 1)*10+(#a_81_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_81_4  & 1)*1) >=13
 
}