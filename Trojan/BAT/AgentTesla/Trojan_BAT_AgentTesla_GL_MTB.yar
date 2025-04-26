
rule Trojan_BAT_AgentTesla_GL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 20 [0-04] 20 01 00 00 00 ?? fe 0e 0b 00 } //1
		$a_02_1 = {48 68 d3 13 0a 38 ?? fa ff ff } //1
		$a_01_2 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } //1 costura.costura.dll.compressed
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_GL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_03_0 = {50 68 61 72 6d 61 63 79 [0-0f] 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //10
		$a_81_1 = {45 78 70 65 6e 73 65 4d 61 6e 61 67 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //10 ExpenseManager.Properties.Resources
		$a_81_2 = {47 65 74 78 78 78 } //1 Getxxx
		$a_81_3 = {53 65 74 78 78 78 } //1 Setxxx
		$a_81_4 = {46 72 6f 6d 42 61 73 65 36 34 } //1 FromBase64
		$a_81_5 = {46 6c 6f 72 61 } //1 Flora
		$a_81_6 = {47 65 74 4d 65 74 68 6f 64 } //1 GetMethod
		$a_81_7 = {49 6e 76 6f 6b 65 } //1 Invoke
		$a_81_8 = {46 6f 72 6d 31 } //1 Form1
	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=17
 
}
rule Trojan_BAT_AgentTesla_GL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.GL!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 73 65 36 34 53 74 72 69 6e 67 00 52 65 70 6c 61 63 65 00 } //1 獡㙥匴牴湩g敒汰捡e
		$a_01_1 = {1e 1e 0d 0d 0d 0d 0d 1e 1e 0d 0d 0d 57 64 ab 11 } //1
		$a_01_2 = {61 6d 20 74 72 6e 6e 6f 74 20 73 76 20 72 75 6e } //2 am trnnot sv run
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=2
 
}