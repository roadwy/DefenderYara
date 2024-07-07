
rule Trojan_BAT_AgentTesla_NEL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 75 78 69 57 65 62 5f 4d 53 70 72 74 } //3 AuxiWeb_MSprt
		$a_01_1 = {48 50 5a 33 52 77 73 5f 57 65 62 5f 48 66 6f 33 32 } //3 HPZ3Rws_Web_Hfo32
		$a_01_2 = {6b 62 64 5f 50 6f 74 63 61 } //3 kbd_Potca
		$a_01_3 = {65 70 30 69 63 65 73 5f 50 72 6f 70 64 4d 74 70 } //3 ep0ices_PropdMtp
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3) >=12
 
}
rule Trojan_BAT_AgentTesla_NEL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NEL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 37 35 41 39 33 43 34 2d 43 36 36 34 2d 34 32 36 35 2d 42 41 41 35 2d 43 36 34 38 42 30 34 35 46 35 32 30 } //1 A75A93C4-C664-4265-BAA5-C648B045F520
		$a_01_1 = {00 47 65 74 50 69 78 65 6c 00 } //1 䜀瑥楐數l
		$a_01_2 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_01_3 = {00 43 6f 6c 6f 72 54 72 61 6e 73 6c 61 74 6f 72 00 } //1
		$a_01_4 = {00 54 6f 57 69 6e 33 32 00 } //1
		$a_01_5 = {00 44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 } //1
		$a_01_6 = {00 47 65 74 54 79 70 65 46 72 6f 6d 48 61 6e 64 6c 65 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}