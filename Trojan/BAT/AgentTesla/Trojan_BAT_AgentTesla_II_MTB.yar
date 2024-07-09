
rule Trojan_BAT_AgentTesla_II_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.II!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {11 07 07 11 13 20 ?? ?? ?? ff 20 ?? ?? ?? 00 6f ?? ?? ?? 0a 9e 11 07 07 8f ?? ?? ?? 01 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 11 07 07 94 1f 9c 32 0e 11 07 07 94 1f 64 30 06 11 11 17 58 13 11 07 17 58 0b 07 11 07 8e 69 32 ae } //10
		$a_81_1 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_81_2 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}
rule Trojan_BAT_AgentTesla_II_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.II!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 09 00 00 "
		
	strings :
		$a_01_0 = {57 dd a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 71 00 00 00 26 00 00 00 db 00 00 00 12 02 00 00 a7 } //10
		$a_01_1 = {57 df a2 ff 09 0e 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 77 00 00 00 2b 00 00 00 e1 00 00 00 43 02 00 00 b5 } //10
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_01_3 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_4 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_5 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_6 = {55 70 6c 6f 61 64 46 69 6c 65 } //1 UploadFile
		$a_01_7 = {52 65 76 65 72 73 65 } //1 Reverse
		$a_01_8 = {5a 69 70 46 69 6c 65 } //1 ZipFile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=17
 
}