
rule TrojanDownloader_BAT_AgentTesla_AL_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.AL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {09 11 04 6f 33 90 01 02 0a 00 11 04 6f 34 90 01 02 0a 80 10 90 01 02 04 16 13 05 2b 1f 90 0a 3c 00 72 3d 90 01 02 70 0a 06 28 2f 90 01 02 0a 0b 07 6f 30 90 01 02 0a 0c 08 6f 31 90 01 02 0a 0d 73 32 90 01 02 0a 13 04 90 00 } //3
		$a_03_1 = {d2 9c 00 11 05 17 58 13 05 90 0a 1e 00 7e 10 90 01 02 04 11 05 7e 10 90 01 02 04 11 05 91 20 70 90 01 02 00 59 90 00 } //3
		$a_01_2 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}