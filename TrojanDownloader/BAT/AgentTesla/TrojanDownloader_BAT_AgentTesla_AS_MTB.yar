
rule TrojanDownloader_BAT_AgentTesla_AS_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 09 00 00 "
		
	strings :
		$a_03_0 = {2c 21 69 16 2d 17 2b 60 2b 0e 00 2b 5e 2b 5f 08 91 6f 29 90 01 02 0a 00 00 08 25 17 59 0c 16 25 2d fb fe 02 90 0a 36 00 72 71 90 01 02 70 2b 5e 38 63 90 01 02 00 38 64 90 01 02 00 8e 1d 90 00 } //2
		$a_03_1 = {13 04 2b 00 19 2c cf 11 04 2a 90 0a 12 00 06 6f 2a 90 01 02 0a 0b 07 90 00 } //2
		$a_01_2 = {57 65 62 43 6c 69 65 6e 74 } //1 WebClient
		$a_01_3 = {44 61 74 65 54 69 6d 65 } //1 DateTime
		$a_01_4 = {6f 70 5f 47 72 65 61 74 65 72 54 68 61 6e } //1 op_GreaterThan
		$a_01_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_01_6 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_7 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
		$a_01_8 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=11
 
}