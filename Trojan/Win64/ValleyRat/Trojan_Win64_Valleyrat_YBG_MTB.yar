
rule Trojan_Win64_Valleyrat_YBG_MTB{
	meta:
		description = "Trojan:Win64/Valleyrat.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 e8 ?? ?? ?? ?? 48 83 c4 28 e9 } //1
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 78 00 66 00 6f 00 6c 00 64 00 65 00 72 00 33 00 32 00 5f 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 36 00 34 00 5f 00 6d 00 75 00 74 00 65 00 78 00 } //1 Global\xfolder32_svchost64_mutex
		$a_01_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 78 00 66 00 6f 00 6c 00 64 00 65 00 72 00 33 00 32 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 36 00 34 00 2e 00 65 00 78 00 65 00 } //1 C:\ProgramData\xfolder32\svchost64.exe
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}