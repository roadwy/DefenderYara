
rule Trojan_Win32_Dridex_GC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 ?? 89 45 ?? 66 c7 45 [0-20] 66 81 7d [0-20] 8b 45 ?? 8b 4d ?? 89 4d ?? 8b 4d ?? 39 c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc [0-0a] cc [0-0a] cc } //10
		$a_80_1 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } //llosewwq.ll  2
		$a_80_2 = {2e 70 64 62 } //.pdb  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2) >=10
 
}
rule Trojan_Win32_Dridex_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_02_0 = {c7 44 24 08 0e 00 00 00 [0-08] 89 4c 24 [0-0a] e8 } //1
		$a_02_1 = {cc cc 40 cc eb ?? 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb ?? 8b 44 24 ?? ff 80 ?? ?? ?? ?? 31 c0 c3 c3 } //10
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  10
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*10+(#a_80_2  & 1)*10) >=21
 
}
rule Trojan_Win32_Dridex_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 [0-28] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 53 00 cc [0-0c] cc [0-0c] cc } //10
		$a_80_1 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  2
		$a_80_2 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  2
		$a_80_3 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  2
		$a_80_4 = {66 66 74 79 2e 70 64 62 } //ffty.pdb  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=14
 
}
rule Trojan_Win32_Dridex_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 "
		
	strings :
		$a_02_0 = {69 88 b4 24 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 74 c6 84 24 ?? ?? ?? ?? 75 c6 84 24 ?? ?? ?? ?? 61 c6 84 24 ?? ?? ?? ?? 6c 8b 84 24 ?? ?? ?? ?? 35 ?? ?? ?? ?? c6 84 24 ?? ?? ?? ?? 41 } //10
		$a_02_1 = {4c 00 64 00 72 00 47 00 65 00 74 00 50 00 72 00 6f 00 63 00 65 00 64 00 75 00 72 00 65 00 41 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 79 00 } //10
		$a_02_2 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 79 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10) >=20
 
}
rule Trojan_Win32_Dridex_GC_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 05 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 [0-14] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc [0-0c] cc [0-0c] cc } //10
		$a_80_1 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  2
		$a_80_2 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  2
		$a_80_3 = {4d 61 6e 79 76 76 65 72 73 69 6f 6e 6e 64 61 69 6c 79 6b 4c 69 74 6f 72 61 6e 69 6d 61 6c } //ManyvversionndailykLitoranimal  2
		$a_80_4 = {67 67 70 6c 6f 65 45 52 2e 64 6c 6c } //ggploeER.dll  2
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2) >=14
 
}
rule Trojan_Win32_Dridex_GC_MTB_7{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 07 00 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 [0-0f] 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc [0-0a] cc [0-0a] cc } //10
		$a_02_1 = {8b 04 24 64 a3 00 00 00 00 [0-0f] 83 ec 04 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc [0-0a] cc [0-0a] cc } //10
		$a_02_2 = {8b 04 24 64 a3 00 00 00 00 [0-0f] 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc [0-0a] cc [0-0a] cc } //10
		$a_80_3 = {62 42 4f 4c 4c 50 49 55 } //bBOLLPIU  2
		$a_80_4 = {67 70 6f 69 72 65 65 } //gpoiree  2
		$a_80_5 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  2
		$a_80_6 = {2e 70 64 62 } //.pdb  2
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_02_2  & 1)*10+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*2+(#a_80_6  & 1)*2) >=10
 
}