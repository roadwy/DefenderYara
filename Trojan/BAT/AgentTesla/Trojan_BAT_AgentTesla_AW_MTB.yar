
rule Trojan_BAT_AgentTesla_AW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 55 01 00 00 95 e0 95 7e 0d 00 00 04 20 47 0e 00 00 95 61 7e 0d 00 00 04 20 f8 07 00 00 95 2e 03 17 2b 03 16 06 0a } //2
		$a_01_1 = {20 76 04 00 00 95 e0 95 7e 0d 00 00 04 20 83 01 00 00 95 61 7e 0d 00 00 04 20 2f 0d 00 00 95 2e 03 17 2b 01 16 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}
rule Trojan_BAT_AgentTesla_AW_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 07 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 73 65 72 76 65 72 2e 74 78 74 } //3 Application Data\server.txt
		$a_01_1 = {47 65 74 46 6f 6c 64 65 72 50 61 74 68 } //3 GetFolderPath
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //3 FromBase64String
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //3 DownloadFile
		$a_00_4 = {57 15 a2 01 09 01 00 00 00 fa 01 33 00 16 } //3
		$a_00_5 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 } //3 discordapp.com/attachments
		$a_00_6 = {54 00 56 00 71 00 51 00 41 00 } //3 TVqQA
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3+(#a_00_6  & 1)*3) >=18
 
}