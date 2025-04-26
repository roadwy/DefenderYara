
rule Trojan_Win64_CryptInject_AY_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 54 55 33 4c 6a 49 30 4e 53 34 79 4e 44 51 75 4e 6a 63 3d } //1 MTU3LjI0NS4yNDQuNjc=
		$a_01_1 = {70 6f 72 74 70 6f 72 74 70 6f 72 74 } //1 portportport
		$a_01_2 = {43 3a 5c 57 49 4e 44 4f 57 53 5c 53 59 53 54 45 4d 33 32 5c 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 25 73 2c 20 72 75 6e } //1 C:\WINDOWS\SYSTEM32\rundll32.exe %s, run
		$a_01_3 = {53 54 41 47 45 31 } //1 STAGE1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_CryptInject_AY_MTB_2{
	meta:
		description = "Trojan:Win64/CryptInject.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 c8 b8 ?? ?? ?? ?? 48 03 cb 48 03 cd 48 83 c5 ?? 42 0f b6 8c 21 ?? ?? ?? ?? f7 ee c1 fa 03 8b c2 c1 e8 1f 03 d0 48 63 c6 83 c6 01 4c 63 c2 4d 6b c0 ?? 4c 03 c0 48 8b 44 24 ?? 43 32 8c 20 ?? ?? ?? ?? 88 4c 28 ?? 48 8d 0d ?? ?? ?? ?? e8 } //2
		$a_03_1 = {4c 63 c0 b8 ?? ?? ?? ?? 4c 03 c3 4c 03 c5 f7 ee c1 fa 03 8b c2 c1 e8 1f 03 c2 48 98 48 8d 0c c0 48 63 c6 83 c6 01 48 8d 14 88 41 8a 8c 38 ?? ?? ?? ?? 48 8b 44 24 ?? 32 8c 3a ?? ?? ?? ?? 88 0c 28 48 8d 0d ?? ?? ?? ?? 48 83 c5 01 e8 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=2
 
}