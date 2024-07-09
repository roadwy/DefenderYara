
rule TrojanDownloader_BAT_AgentTesla_F_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {2b 11 06 a2 25 1f 14 28 ?? 00 00 2b 1f 18 28 ?? 00 00 2b 8c ?? 00 00 01 a2 13 90 09 16 00 a2 25 1f ?? 28 ?? 00 00 2b 7e ?? 00 00 0a a2 25 1f 10 28 } //2
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {52 65 61 64 54 6f 45 6e 64 } //1 ReadToEnd
		$a_01_4 = {47 65 74 54 79 70 65 } //1 GetType
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}