
rule Trojan_BAT_AgentTesla_MAA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 38 16 00 00 00 08 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f 90 01 03 0a 09 17 58 0d 09 02 8e 90 00 } //10
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_2 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}