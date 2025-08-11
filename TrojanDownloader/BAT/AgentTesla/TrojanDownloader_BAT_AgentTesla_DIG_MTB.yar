
rule TrojanDownloader_BAT_AgentTesla_DIG_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.DIG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 76 58 43 72 77 62 2f 63 61 30 6b 4f 35 53 4e 33 6c 77 6a 62 77 3d 3d } //1 evXCrwb/ca0kO5SN3lwjbw==
		$a_81_1 = {58 50 54 63 41 37 4c 47 66 35 52 36 4a 62 65 73 68 38 2e 6a 49 75 4e 6b 30 6c 31 50 77 59 79 76 32 62 45 46 64 } //1 XPTcA7LGf5R6Jbesh8.jIuNk0l1PwYyv2bEFd
		$a_81_2 = {28 4d 61 63 69 6e 74 6f 73 68 3b 20 49 6e 74 65 6c 20 4d 61 63 20 4f 53 20 58 20 31 33 5f 33 5f 31 29 } //1 (Macintosh; Intel Mac OS X 13_3_1)
		$a_81_3 = {68 74 74 70 73 3a 2f 2f 66 69 6c 65 73 2e 63 61 74 62 6f 78 2e 6d 6f 65 2f 6a 74 79 36 61 32 2e 77 61 76 } //2 https://files.catbox.moe/jty6a2.wav
		$a_81_4 = {4c 65 73 77 76 62 65 62 64 2e 65 78 65 } //1 Leswvbebd.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*2+(#a_81_4  & 1)*1) >=6
 
}