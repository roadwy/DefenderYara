
rule Trojan_BAT_AgentTesla_NKD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de 0d } //1
		$a_80_1 = {64 73 66 67 64 73 66 73 64 66 73 64 } //dsfgdsfsdfsd  1
		$a_01_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_4 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_80_5 = {53 79 73 2e 53 79 73 } //Sys.Sys  1
	condition:
		((#a_03_0  & 1)*1+(#a_80_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}