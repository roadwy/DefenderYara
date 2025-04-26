
rule Backdoor_Win32_Zloader_SD_MTB{
	meta:
		description = "Backdoor:Win32/Zloader.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 6d 70 2e 74 78 74 } //1 tmp.txt
		$a_03_1 = {00 d0 89 c3 89 d8 8b 4d 08 00 c8 f6 e2 30 d8 0f be c0 a3 ?? ?? ?? ?? 89 f8 5e 5f 5b 5d c3 } //1
		$a_03_2 = {8b 4d 0c 85 c9 0f 84 ?? 00 00 00 a1 ?? ?? ?? ?? 0f be 18 66 33 1e 66 89 19 0f 84 ?? 00 00 00 31 ff e9 ?? 00 00 00 } //1
	condition:
		((#a_81_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}