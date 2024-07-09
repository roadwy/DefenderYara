
rule TrojanDownloader_BAT_AgentTesla_EOQ_MTB{
	meta:
		description = "TrojanDownloader:BAT/AgentTesla.EOQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {06 02 50 08 91 8c ?? ?? ?? 01 6f ?? ?? ?? 0a 26 00 08 25 17 59 0c 16 fe 02 0d 09 2d } //1
		$a_01_1 = {2f 00 63 00 20 00 70 00 69 00 6e 00 67 00 20 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 20 00 26 00 26 00 20 00 74 00 69 00 6d 00 65 00 6f 00 75 00 74 00 20 00 31 00 30 00 } //1 /c ping google.com && timeout 10
		$a_01_2 = {00 47 65 74 4d 65 74 68 6f 64 00 } //1
		$a_01_3 = {00 47 65 74 54 79 70 65 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}