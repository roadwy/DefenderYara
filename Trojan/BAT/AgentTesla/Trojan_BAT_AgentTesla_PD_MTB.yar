
rule Trojan_BAT_AgentTesla_PD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {02 16 9a 28 90 01 04 0a 02 17 9a 75 90 01 04 06 6f 90 01 04 28 90 01 04 06 7e 90 01 04 6f 90 01 04 5d 0b 7e 90 01 04 0c 08 07 6f 90 01 04 61 8c 90 01 04 2a 90 00 } //1
		$a_03_1 = {16 0a 2b 35 00 28 90 01 04 73 90 01 04 72 90 01 04 28 90 01 04 6f 1f 00 00 0a 16 6a 28 90 01 04 28 90 01 04 de 0d 26 17 0a 28 90 01 04 de 03 90 00 } //1
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //1 DownloadData
		$a_01_3 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_4 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 2e 00 30 00 2e 00 33 00 30 00 33 00 31 00 39 00 5c 00 41 00 64 00 64 00 49 00 6e 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 33 00 32 00 2e 00 65 00 78 00 65 00 } //1 C:\Windows\Microsoft.NET\Framework\v4.0.30319\AddInProcess32.exe
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_PD_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 8f 6d 00 00 01 25 47 02 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}