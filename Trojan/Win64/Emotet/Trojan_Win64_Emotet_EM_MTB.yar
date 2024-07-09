
rule Trojan_Win64_Emotet_EM_MTB{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 c8 f7 ea d1 fa 89 c8 c1 f8 1f 89 d3 29 c3 89 d8 6b c0 37 89 ce 29 c6 89 f0 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_2{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 29 d1 4d 63 c9 42 0f b6 04 08 32 04 0b 41 88 04 08 48 83 c1 01 4c 39 d9 75 c2 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 c1 ea 04 89 55 ?? 81 45 ?? ?? ?? ?? ?? 81 75 ?? ?? ?? ?? ?? c7 45 ?? ?? ?? ?? ?? c1 65 ?? ?? 81 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_4{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c7 8b cf 2b c2 ff c7 d1 e8 03 c2 c1 e8 05 6b c0 3f 2b c8 48 63 c1 42 0f b6 04 20 41 32 44 2e ff 41 88 46 ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win64_Emotet_EM_MTB_5{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 32 44 0c 20 49 2b d2 4a 8d 0c 5d fe ff ff ff 49 0f af d1 49 2b d2 49 03 d3 48 0f af c1 48 03 c7 48 ff c7 48 8d 0c 50 46 88 04 31 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_6{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 b4 44 89 c0 89 55 b0 99 44 8b 45 b4 41 f7 f8 4c 63 ca 42 0f b6 14 09 44 8b 55 b0 41 31 d2 45 88 d3 48 8b 8d d0 0b 00 00 8b 55 18 2b 55 1c 03 55 1c 4c 63 ca 46 88 1c 09 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_7{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 7a 6b 45 4e 54 6d 42 56 } //1 yzkENTmBV
		$a_01_1 = {7a 51 6e 46 6b 45 73 67 6c 76 53 6d 59 74 4b 6c 6b 46 44 54 6d 65 } //1 zQnFkEsglvSmYtKlkFDTme
		$a_01_2 = {7a 64 4d 68 59 77 } //1 zdMhYw
		$a_01_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } //1 OutputDebugStringW
		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } //1 CreateFileW
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Emotet_EM_MTB_8{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 47 5a 6c 66 6b 6b 67 3f 55 5e 3e 2b 78 7a 55 35 25 51 5f 3e 38 53 79 31 32 50 77 53 44 74 30 4d 63 52 6e 71 } //2 vGZlfkkg?U^>+xzU5%Q_>8Sy12PwSDt0McRnq
		$a_01_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //1 DllRegisterServer
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //1 VirtualAlloc
		$a_01_3 = {43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 } //1 CreateToolhelp32Snapshot
		$a_01_4 = {4a 75 63 51 42 32 52 31 70 73 5a 6d 74 72 5a 77 3d 3d } //1 JucQB2R1psZmtrZw==
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}