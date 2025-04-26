
rule Trojan_BAT_AgentTesla_HT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.HT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {53 75 62 46 72 61 6d 65 43 61 6c 63 75 6c 61 74 6f 72 2e 52 65 73 6f 75 72 63 65 73 } //1 SubFrameCalculator.Resources
		$a_81_1 = {24 33 38 63 65 63 38 62 62 2d 63 30 31 33 2d 34 37 35 66 2d 39 38 62 34 2d 35 65 63 30 35 64 34 31 66 34 36 62 } //1 $38cec8bb-c013-475f-98b4-5ec05d41f46b
		$a_81_2 = {2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f } //1 //cdn.discordapp.com/attachments/
		$a_81_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_4 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //1 DownloadString
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}