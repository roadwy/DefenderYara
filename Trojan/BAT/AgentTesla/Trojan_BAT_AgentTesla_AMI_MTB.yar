
rule Trojan_BAT_AgentTesla_AMI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 5c 44 65 73 6b 74 6f 70 5c 4e 65 77 20 66 6f 6c 64 65 72 5c 62 69 6e 5c 44 65 62 75 67 5c 53 4c 4e 5c 44 69 61 72 79 5c 6f 62 6a 5c 44 65 62 75 67 5c 44 69 61 72 79 2e 70 64 62 } //01 00  C:\Users\Administrator\Desktop\New folder\bin\Debug\SLN\Diary\obj\Debug\Diary.pdb
		$a_01_1 = {4c 00 69 00 62 00 72 00 61 00 72 00 79 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 6d 00 65 00 6e 00 74 00 20 00 41 00 70 00 70 00 } //00 00  Library Management App
	condition:
		any of ($a_*)
 
}