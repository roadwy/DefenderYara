
rule Trojan_Win32_Qakbot_MG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 46 34 40 0f af 46 44 89 46 44 8b 46 14 2d ?? ?? ?? ?? 31 46 18 8b 46 68 35 ?? ?? ?? ?? 29 46 48 8b 86 ?? ?? ?? ?? 09 86 ?? ?? ?? ?? 8b 86 ?? ?? ?? ?? 01 86 ?? ?? ?? ?? 81 fb ?? ?? ?? ?? 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_MG_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 "
		
	strings :
		$a_01_0 = {d9 fc 7a 65 d8 ba 08 00 3d bb 08 00 3d ee 66 6d dc ca 5e 69 d8 cb 47 66 83 d2 64 65 3d bb 08 } //10
		$a_01_1 = {19 de 40 61 13 df 64 65 f2 ba 08 00 fe c8 6d 61 11 de 4e 69 11 de 49 00 3d bb 08 00 3d bb 08 53 e0 ce 4e 69 d1 dd 58 6f e4 d4 7c 65 cf ba 08 } //10
		$a_01_2 = {47 65 74 4b 65 79 62 6f 61 72 64 54 79 70 65 } //2 GetKeyboardType
		$a_01_3 = {47 65 74 54 68 72 65 61 64 4c 6f 63 61 6c 65 } //2 GetThreadLocale
		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //2 WaitForSingleObject
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=26
 
}
rule Trojan_Win32_Qakbot_MG_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {6c 63 6d 73 31 35 46 69 78 65 64 31 36 74 6f 44 6f 75 62 6c 65 } //1 lcms15Fixed16toDouble
		$a_01_1 = {6c 63 6d 73 43 61 6c 6c 6f 63 } //1 lcmsCalloc
		$a_01_2 = {6c 63 6d 73 43 72 65 61 74 65 4d 75 74 65 78 } //1 lcmsCreateMutex
		$a_01_3 = {6c 63 6d 73 44 65 73 74 72 6f 79 4d 75 74 65 78 } //1 lcmsDestroyMutex
		$a_01_4 = {6c 63 6d 73 47 65 74 54 72 61 6e 73 66 6f 72 6d 46 6f 72 6d 61 74 74 65 72 73 31 36 } //1 lcmsGetTransformFormatters16
		$a_01_5 = {6c 63 6d 73 4c 6f 63 6b 4d 75 74 65 78 } //1 lcmsLockMutex
		$a_01_6 = {6c 63 6d 73 4d 41 54 33 73 6f 6c 76 65 } //1 lcmsMAT3solve
		$a_01_7 = {6c 6d 73 43 49 45 43 41 4d 30 32 52 65 76 65 72 73 65 } //1 lmsCIECAM02Reverse
		$a_01_8 = {6e 65 78 74 } //1 next
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}