
rule Trojan_Win32_Zusy_MB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 38 d8 c2 d8 ea d8 ca d8 d1 d8 d0 d8 d4 89 10 d8 d1 d8 c0 88 10 d8 c5 d8 e1 d8 ec d8 c8 d8 db 8a 0c d8 d4 d8 df d8 cd d8 e1 d8 e2 d8 c7 d8 d8 } //10
		$a_01_1 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } //10 FGBHNJMK.DLL
		$a_01_2 = {46 66 67 62 48 67 79 62 68 } //1 FfgbHgybh
		$a_01_3 = {46 67 62 79 68 6e 4b 6a 67 76 } //1 FgbyhnKjgv
		$a_01_4 = {54 74 66 76 79 67 62 4b 68 62 67 66 } //1 TtfvygbKhbgf
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}
rule Trojan_Win32_Zusy_MB_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_01_0 = {4e 69 6b 73 72 6a 67 68 73 72 6f 6a 41 69 73 6a 68 69 72 6a 68 } //2 NiksrjghsrojAisjhirjh
		$a_01_1 = {4e 6f 66 64 6f 68 6a 41 64 68 6f 64 72 6a 68 6f 72 73 68 6a } //2 NofdohjAdhodrjhorshj
		$a_01_2 = {4f 6a 73 6a 73 6f 66 6a 41 73 6a 68 67 73 72 69 6a 68 72 } //2 OjsjsofjAsjhgsrijhr
		$a_01_3 = {53 65 74 50 72 6f 63 65 73 73 50 72 69 6f 72 69 74 79 42 6f 6f 73 74 } //1 SetProcessPriorityBoost
		$a_01_4 = {53 65 74 54 68 72 65 61 64 4c 6f 63 61 6c 65 } //1 SetThreadLocale
		$a_01_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 WriteProcessMemory
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}