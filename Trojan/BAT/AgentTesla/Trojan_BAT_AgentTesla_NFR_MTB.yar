
rule Trojan_BAT_AgentTesla_NFR_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_03_0 = {20 00 d0 00 00 8d 90 01 01 00 00 01 90 00 } //1
		$a_01_1 = {24 32 36 65 30 61 37 64 36 2d 64 64 35 39 2d 34 37 64 30 2d 39 32 62 34 2d 35 32 31 39 61 64 31 38 35 65 33 38 } //1 $26e0a7d6-dd59-47d0-92b4-5219ad185e38
		$a_81_2 = {53 79 73 74 65 6d 2e 41 63 74 69 76 61 74 6f 72 } //1 System.Activator
		$a_81_3 = {69 4f 2e 66 6f } //1 iO.fo
		$a_81_4 = {47 65 74 50 69 78 65 6c } //1 GetPixel
		$a_81_5 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_6 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_7 = {54 6f 57 69 6e 33 32 } //1 ToWin32
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}
rule Trojan_BAT_AgentTesla_NFR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 00 72 00 00 05 65 00 73 00 00 05 6f 00 75 00 00 05 72 00 63 00 00 0d 48 00 4e 00 48 00 4a 00 47 00 35 00 00 0f 6b 00 6a 00 68 00 79 00 75 00 37 00 69 00 00 09 67 00 68 00 68 00 67 00 00 09 6a 00 72 00 77 } //1
		$a_81_1 = {23 23 23 23 53 79 73 23 23 74 65 6d 23 23 23 23 } //1 ####Sys##tem####
		$a_81_2 = {23 23 23 23 52 65 23 23 66 6c 23 23 65 63 23 23 74 69 23 23 6f 6e 23 23 23 23 } //1 ####Re##fl##ec##ti##on####
		$a_81_3 = {47 65 74 4d 61 6e 69 66 65 73 74 52 65 73 6f 75 72 63 65 4e 61 6d 65 } //1 GetManifestResourceName
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}