
rule TrojanDownloader_BAT_AgentTesla_ABFV_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABFV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_03_0 = {2b 31 2b 61 2b 62 72 ?? ?? ?? 70 2b 65 2b 6d 38 ?? ?? ?? 00 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 8e 69 5d 91 06 08 91 61 d2 6f ?? ?? ?? 0a 08 16 2d 04 17 58 0c 08 06 8e } //2
		$a_01_1 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_3 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}