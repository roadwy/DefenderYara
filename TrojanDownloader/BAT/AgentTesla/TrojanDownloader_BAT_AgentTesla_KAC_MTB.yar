
rule TrojanDownloader_BAT_AgentTesla_KAC_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {72 49 00 00 70 28 90 01 01 00 00 06 0d 09 8e 69 13 04 2b 0a 06 09 11 04 91 6f 90 01 01 00 00 0a 11 04 25 17 59 13 04 16 fe 02 2d ea 06 6f 90 00 } //1
		$a_01_1 = {3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 } //1 ://cdn.discordapp.com/attachments/
		$a_01_2 = {67 65 74 5f 4e 6f 77 } //1 get_Now
		$a_01_3 = {41 64 64 53 65 63 6f 6e 64 73 } //1 AddSeconds
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}