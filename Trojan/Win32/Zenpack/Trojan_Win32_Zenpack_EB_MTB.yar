
rule Trojan_Win32_Zenpack_EB_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d8 8b 7d e4 0f b6 14 17 31 d1 88 cb 8b 4d d4 8b 55 e8 88 1c 0a } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff e0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d7 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? 83 f9 67 74 d1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Zenpack_EB_MTB_5{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? 83 f9 0a 74 d1 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Zenpack_EB_MTB_6{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 18 ba 01 00 00 00 4a 8d 05 ?? ?? ?? ?? 31 38 01 c2 4a 8d 05 ?? ?? ?? ?? 01 28 01 c2 4a 8d 05 ?? ?? ?? ?? 89 30 eb cc } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Zenpack_EB_MTB_7{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff ff 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? b9 03 00 00 00 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? e2 d5 31 c0 40 c3 } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Zenpack_EB_MTB_8{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 89 ca 89 25 ?? ?? ?? ?? e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb da } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Zenpack_EB_MTB_9{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 83 ea 05 01 d0 83 f0 01 01 25 ?? ?? ?? ?? 31 d0 29 c2 29 d0 b9 02 00 00 00 e2 2d 4a 83 f2 07 ba 04 00 00 00 8d 05 ?? ?? ?? ?? 31 28 8d 05 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_10{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 b9 03 00 00 00 49 89 ca 89 25 ?? ?? ?? ?? eb 08 8d 05 ?? ?? ?? ?? ff e0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_11{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 d0 b9 03 00 00 00 49 89 ca 89 25 ?? ?? ?? ?? eb 05 e8 ?? ?? ?? ?? 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb da } //7
	condition:
		((#a_03_0  & 1)*7) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_12{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 55 89 e5 eb 25 31 2d ?? ?? ?? ?? 58 a3 ?? ?? ?? ?? 81 05 ?? ?? ?? ?? 04 00 00 00 a1 ?? ?? ?? ?? 66 6a 00 2d 83 11 00 00 ff d0 89 d9 89 0d ?? ?? ?? ?? 89 f1 89 0d ?? ?? ?? ?? 89 3d ?? ?? ?? ?? 39 3d ?? ?? ?? ?? 74 bd } //6
	condition:
		((#a_03_0  & 1)*6) >=6
 
}
rule Trojan_Win32_Zenpack_EB_MTB_13{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff d0 89 da 01 15 ?? ?? ?? ?? 89 f0 01 05 ?? ?? ?? ?? 55 8f 05 ?? ?? ?? ?? 89 f8 01 05 ?? ?? ?? ?? eb d7 89 45 } //5
		$a_01_1 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //1 OutputDebugStringA
		$a_01_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //1 LoadResource
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}
rule Trojan_Win32_Zenpack_EB_MTB_14{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4f 49 6a 38 39 73 67 68 6a 34 73 69 6f 68 6a 72 68 } //1 AOIj89sghj4siohjrh
		$a_01_1 = {49 6f 73 62 76 73 65 72 69 6f 48 6a 65 72 49 73 68 } //1 IosbvserioHjerIsh
		$a_01_2 = {4f 70 78 76 62 73 65 67 65 34 68 72 68 69 72 74 6a } //1 Opxvbsege4hrhirtj
		$a_01_3 = {55 79 69 61 77 73 70 72 67 6a 77 34 30 67 68 73 72 65 68 } //1 Uyiawsprgjw40ghsreh
		$a_01_4 = {69 6f 73 67 6f 34 6a 67 73 72 6f 68 73 6a 72 6f 68 69 } //1 iosgo4jgsrohsjrohi
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Zenpack_EB_MTB_15{
	meta:
		description = "Trojan:Win32/Zenpack.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 00 75 00 6c 00 74 00 69 00 70 00 6c 00 79 00 74 00 4e 00 35 00 54 00 68 00 69 00 6e 00 67 00 71 00 66 00 69 00 66 00 74 00 68 00 } //1 multiplytN5Thingqfifth
		$a_01_1 = {50 00 72 00 65 00 70 00 6c 00 65 00 6e 00 69 00 73 00 68 00 69 00 77 00 68 00 6f 00 73 00 65 00 61 00 44 00 42 00 73 00 } //1 PreplenishiwhoseaDBs
		$a_01_2 = {70 00 79 00 64 00 69 00 76 00 69 00 64 00 65 00 64 00 79 00 6f 00 75 00 2e 00 6c 00 6c 00 6c 00 } //1 pydividedyou.lll
		$a_01_3 = {6d 00 6f 00 76 00 69 00 6e 00 67 00 66 00 6f 00 77 00 6c 00 74 00 68 00 65 00 6c 00 62 00 72 00 69 00 6e 00 67 00 } //1 movingfowlthelbring
		$a_01_4 = {63 00 72 00 65 00 65 00 70 00 69 00 6e 00 67 00 2c 00 4c 00 35 00 48 00 43 00 61 00 6e 00 2e 00 74 00 } //1 creeping,L5HCan.t
		$a_01_5 = {54 00 68 00 65 00 33 00 4c 00 41 00 58 00 69 00 6e 00 2e 00 67 00 49 00 74 00 73 00 65 00 6c 00 66 00 6e 00 } //1 The3LAXin.gItselfn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}