
rule Trojan_Win32_Emotet_BS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 fb 89 55 ?? 03 d7 52 51 e8 ?? ?? ?? ?? 8b 45 ?? 40 3b c6 59 59 89 45 ?? 7c } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BS_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 fb 8b 45 ?? 0f b6 14 10 8b 45 ?? 0f be 1c 08 89 d8 21 d0 09 da 8b 5d ?? f7 d0 21 d0 88 04 0b 41 eb } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BS_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 75 26 00 00 99 f7 f9 8b 45 ?? 8a 08 8a 94 15 ?? ?? ?? ?? 32 ca 88 08 40 89 45 ?? 8b 45 ?? 48 89 45 ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BS_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {03 c3 99 f7 f9 0f b6 04 37 8b da 8a 14 33 88 14 37 88 04 33 0f b6 0c 33 0f b6 04 37 03 c1 } //1
		$a_02_1 = {02 d2 8a cc c0 e9 04 02 d2 0a ca 88 0e 8a 4c 24 ?? 8a d1 8a c4 c0 e0 04 83 c6 01 c0 ea 02 0a d0 c0 e1 06 0a 4c 24 ?? 88 16 83 c6 01 88 0e } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_BS_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {2b f0 89 44 24 ?? 89 74 24 ?? 89 4c 24 ?? b3 06 eb 08 8b 54 24 ?? 8b 7c 24 ?? 8d 42 01 b9 ?? ?? ?? ?? 99 f7 f9 33 c0 8a 04 2a 03 c7 89 54 24 ?? 8d 34 2a 99 f7 f9 } //1
		$a_02_1 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 0f b6 04 32 8b 54 24 10 0f be 3c 17 e8 ?? ?? ?? ?? 8b 4c 24 10 88 01 41 83 6c 24 14 01 89 4c 24 10 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BS_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 00 44 00 53 00 41 00 44 00 46 00 58 00 73 00 73 00 64 00 73 00 64 00 66 00 67 00 67 00 47 00 53 00 44 00 5a 00 43 00 53 00 44 00 65 00 77 00 64 00 } //1 FDSADFXssdsdfggGSDZCSDewd
		$a_00_1 = {75 00 79 00 74 00 79 00 44 00 44 00 7a 00 78 00 73 00 64 00 45 00 51 00 64 00 73 00 73 00 67 00 47 00 47 00 53 00 44 00 53 00 64 00 73 00 } //1 uytyDDzxsdEQdssgGGSDSds
		$a_02_2 = {6a 00 6a 00 6a 00 6a 00 68 ac 04 01 00 68 a7 ad 00 00 68 77 03 00 00 68 6b 03 00 00 68 00 00 80 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 ff 15 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Emotet_BS_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 84 24 ?? ?? ?? ?? 8a 54 14 20 30 14 01 41 89 4c 24 1c 8b 8c 24 ?? ?? ?? ?? 85 c9 0f 85 } //1
		$a_02_1 = {03 c1 8b ce 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85 } //1
		$a_02_2 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 4c 24 1c 8b 44 24 20 83 c1 01 89 4c 24 1c 8a 54 14 24 30 54 08 ff 83 bc 24 ?? ?? ?? ?? 00 0f 85 } //1
		$a_02_3 = {03 c1 99 b9 ?? ?? ?? ?? f7 f9 8b 44 24 24 8a 4c 14 28 30 08 ff 44 24 1c 39 b4 24 ?? ?? ?? ?? 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_BS_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 "
		
	strings :
		$a_02_0 = {b8 5f 33 00 00 85 c0 74 ?? 8b 4d ?? 3b 0d ?? ?? ?? ?? 72 ?? eb ?? 8b 55 ?? 03 55 ?? 8b 45 ?? 03 45 ?? 8b 4d ?? 8b 75 ?? 8a 14 16 88 14 01 8b 45 ?? 83 c0 01 89 45 ?? eb } //3
		$a_02_1 = {83 e9 01 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? b9 01 00 00 00 85 c9 0f } //2
		$a_02_2 = {55 8b ec 51 a1 ?? ?? ?? ?? 89 45 fc eb 00 8b 65 fc 58 8b e8 a1 ?? ?? ?? ?? 50 a1 ?? ?? ?? ?? 50 ff 25 ?? ?? ?? ?? 8b e5 5d c3 } //1
		$a_00_3 = {81 ff d0 08 00 00 74 23 29 c0 48 23 02 83 ea fc 83 c0 dd 01 d8 83 c0 ff 89 c3 c7 01 00 00 00 00 09 01 83 c1 04 83 c7 04 2e } //6
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*2+(#a_02_2  & 1)*1+(#a_00_3  & 1)*6) >=6
 
}