
rule TrojanDownloader_BAT_AgentTesla_ABAO_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.ABAO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_03_0 = {07 08 18 5b 02 08 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 08 18 58 0c 08 06 32 e4 07 2a } //4
		$a_01_1 = {47 65 74 52 65 73 70 6f 6e 73 65 53 74 72 65 61 6d } //1 GetResponseStream
		$a_01_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 39 36 2e 46 6f 72 6d 73 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //1 WindowsFormsApp96.Forms.Form1.resources
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=7
 
}