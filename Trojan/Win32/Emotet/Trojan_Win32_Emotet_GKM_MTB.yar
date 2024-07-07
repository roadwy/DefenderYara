
rule Trojan_Win32_Emotet_GKM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 8b f1 f7 fe 8b 45 90 01 01 8a 90 01 01 15 90 02 04 30 10 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 b9 64 01 00 00 99 f7 f9 8a 03 8a 54 14 90 01 01 32 c2 88 03 43 4d 75 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 5c af 00 00 f7 f9 8a 5d 00 8d 4c 24 90 01 01 8a 94 14 90 01 04 32 da 88 5d 00 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 6b 1c 00 00 f7 f9 45 8a 54 14 90 01 01 30 55 90 01 01 83 bc 24 90 01 05 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 21 d8 00 00 f7 f9 8a 45 00 8d 4c 24 90 01 01 8a 9c 14 90 01 04 32 d8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ce 99 f7 f9 8b 45 90 01 01 83 c4 18 8a 8c 15 90 01 04 30 08 40 ff 4d 90 01 01 89 45 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 e5 08 00 00 f7 f9 8b 4c 24 90 01 01 8b 84 24 90 01 04 8a 1c 01 8a 54 14 90 01 01 32 da 88 1c 01 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 96 16 00 00 f7 f9 8b 44 24 90 01 01 83 c0 01 8b ce 89 44 24 90 01 01 0f b6 94 14 90 01 04 30 50 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 90 01 01 8a 4c 15 00 30 08 40 83 bd 90 01 04 00 89 45 90 01 01 0f 85 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_10{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 72 1b 00 00 f7 f9 8a 5d 00 8b 44 24 90 01 01 8a 54 14 90 01 01 32 da 88 5d 00 45 48 89 44 24 90 01 01 0f 85 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 44 24 90 01 01 8a 08 8a 54 14 90 01 01 32 ca 88 08 40 89 44 24 90 01 01 8b 44 24 90 01 01 48 89 44 24 90 01 01 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_12{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 8b ce f7 f9 8b 45 90 01 01 83 4d 90 01 02 8a 8c 15 90 01 04 30 08 40 8d 8d 90 01 04 89 45 90 01 01 e8 90 01 04 ff 4d 90 01 01 75 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 44 24 90 01 01 8b 8c 24 90 01 04 8a 54 14 90 01 01 30 14 08 40 89 44 24 90 01 01 8b 84 24 90 01 04 8b c8 48 85 c9 89 84 24 90 01 04 0f 85 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 20 04 00 00 f7 f9 8a 5d 00 8b 44 24 90 01 01 8a 54 14 90 01 01 32 da 88 5d 00 90 00 } //1
		$a_02_1 = {03 c1 99 b9 20 04 00 00 f7 f9 45 0f b6 54 14 90 01 01 30 55 ff 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_GKM_MTB_15{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 84 24 90 01 04 8a 08 8a 94 14 90 01 04 32 ca 88 08 40 89 84 24 90 01 04 8b 84 24 90 01 04 48 89 84 24 90 01 04 0f 85 90 00 } //2
		$a_02_1 = {b9 28 11 00 00 99 f7 f9 8a 5d 00 8b 44 24 90 01 01 8a 54 14 90 01 01 32 da 88 5d 00 90 00 } //2
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}
rule Trojan_Win32_Emotet_GKM_MTB_16{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 be 33 06 01 00 f7 f6 41 81 f9 33 06 01 00 8b f2 8a 44 34 90 01 01 88 44 0c 90 01 01 88 5c 34 90 01 01 72 90 00 } //1
		$a_02_1 = {33 d2 be 53 88 00 00 f7 f6 41 81 f9 53 88 00 00 8b f2 8a 44 34 90 01 01 88 44 0c 90 01 01 88 5c 34 90 01 01 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}