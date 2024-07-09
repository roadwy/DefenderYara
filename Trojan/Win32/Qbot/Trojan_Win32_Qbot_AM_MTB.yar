
rule Trojan_Win32_Qbot_AM_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 4c 52 35 33 73 64 53 57 } //2 ALR53sdSW
		$a_01_1 = {41 4d 69 48 51 37 } //2 AMiHQ7
		$a_01_2 = {42 56 62 49 56 63 34 67 32 } //2 BVbIVc4g2
		$a_01_3 = {42 5a 38 57 6b 43 } //2 BZ8WkC
		$a_01_4 = {42 66 33 50 35 45 36 } //2 Bf3P5E6
		$a_01_5 = {43 4e 79 35 73 71 33 4c 4d 72 65 } //2 CNy5sq3LMre
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=12
 
}
rule Trojan_Win32_Qbot_AM_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_1 = {44 6d 45 43 4d 48 5a 54 } //1 DmECMHZT
		$a_01_2 = {49 4d 6b 53 45 32 47 6f 69 } //1 IMkSE2Goi
		$a_01_3 = {4e 4c 35 75 30 33 } //1 NL5u03
		$a_01_4 = {50 49 39 50 56 46 33 7a 4c 57 35 } //1 PI9PVF3zLW5
		$a_01_5 = {54 44 65 35 6e 65 30 56 56 39 } //1 TDe5ne0VV9
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Qbot_AM_MTB_3{
	meta:
		description = "Trojan:Win32/Qbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 53 69 6a 7a 43 66 59 77 45 78 } //1 DSijzCfYwEx
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {46 43 5a 45 72 38 59 45 7a 37 } //1 FCZEr8YEz7
		$a_01_3 = {47 67 6b 41 57 48 6f 35 4f 4c 70 } //1 GgkAWHo5OLp
		$a_01_4 = {4b 52 69 79 31 59 62 6c 6e 36 6f } //1 KRiy1Ybln6o
		$a_01_5 = {53 39 4e 41 67 39 43 } //1 S9NAg9C
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_Qbot_AM_MTB_4{
	meta:
		description = "Trojan:Win32/Qbot.AM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 03 4d ?? 89 4d ?? 0f b6 15 ?? ?? ?? ?? 8b 45 ?? 2b c2 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 03 45 ?? 89 45 ?? 0f b6 0d ?? ?? ?? ?? 8b 55 ?? 2b d1 89 55 ?? 0f b6 05 ?? ?? ?? ?? 33 45 ?? 89 45 } //2
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}