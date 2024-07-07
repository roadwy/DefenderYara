
rule Trojan_Win32_Emotet_MX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 8f 02 00 00 99 f7 f9 8a 03 8a 54 14 90 01 01 32 c2 88 03 43 4d 0f 85 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MX_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 73 0c 00 00 f7 f9 8b 45 90 01 01 8a 4c 15 00 30 08 40 39 9d 8c 0c 00 00 89 45 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MX_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {b9 58 10 00 00 f7 f9 8b 4c 24 90 01 01 8b 84 24 90 01 04 8a 1c 01 8a 54 14 90 01 01 32 da 88 1c 01 41 3b ee 89 4c 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MX_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 f7 bd 90 01 04 0f b6 94 15 90 01 04 8b 45 10 03 85 90 01 04 0f b6 08 33 ca 8b 55 90 01 01 03 95 90 01 04 88 0a 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MX_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c0 3b f3 7e 90 01 01 8b 4d 90 01 01 8d 4c 31 90 01 01 8a 11 88 90 01 05 40 49 3b c6 7c 90 00 } //1
		$a_02_1 = {52 53 6a 01 53 50 ff 15 90 01 04 85 c0 0f 95 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_MX_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 ff 03 00 00 f7 f9 8b 44 24 90 01 01 8b 4c 24 90 01 01 40 89 44 24 90 01 01 8a 54 14 90 01 01 30 54 01 ff 8d 4c 24 90 01 01 c7 84 24 3c 04 00 00 ff ff ff ff e8 90 01 04 39 ac 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Emotet_MX_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {30 14 08 40 89 84 24 90 01 04 8b 84 24 90 01 04 8b c8 48 85 c9 89 84 24 90 01 04 0f 85 90 00 } //1
		$a_80_1 = {43 6b 77 34 63 71 4b 37 67 64 36 4a 35 6c 76 34 4a 42 5a 39 33 4d 50 73 7a 74 72 30 66 68 } //Ckw4cqK7gd6J5lv4JBZ93MPsztr0fh  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_MX_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 45 90 01 01 8a 8c 15 90 01 04 30 08 40 ff 4d 90 01 01 89 45 90 00 } //1
		$a_80_1 = {36 58 66 75 41 66 6a 4b 74 46 72 57 39 4a 70 58 30 53 35 43 33 78 55 34 58 54 70 62 6c 7a 4c 68 45 70 61 58 57 } //6XfuAfjKtFrW9JpX0S5C3xU4XTpblzLhEpaXW  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_MX_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {f7 f9 8b 44 24 90 01 01 83 c0 01 89 44 24 90 01 01 8a 54 14 90 01 01 30 50 ff 39 ac 24 90 01 04 0f 85 90 00 } //1
		$a_80_1 = {4f 4e 35 44 42 70 6e 6f 58 72 61 52 50 63 4c 66 48 7a 63 32 6c 38 45 42 72 44 4c 76 74 50 7a 34 53 6a } //ON5DBpnoXraRPcLfHzc2l8EBrDLvtPz4Sj  1
	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Emotet_MX_MTB_10{
	meta:
		description = "Trojan:Win32/Emotet.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f9 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 0a 33 f7 2b c6 8b f0 c1 ee 90 01 01 03 35 90 01 04 8b f8 c1 e7 90 01 01 03 3d 90 01 04 33 f7 8d 3c 02 33 f7 2b ce 81 c2 90 01 04 83 6d 90 01 02 75 90 01 01 8b 90 01 02 5f 89 0a 89 90 01 02 5e 8b e5 5d c2 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}