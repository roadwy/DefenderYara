
rule Trojan_Win32_Dridex_GC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 75 90 01 01 88 14 06 83 c0 90 01 01 89 45 90 01 01 66 c7 45 90 02 20 66 81 7d 90 02 20 8b 45 90 01 01 8b 4d 90 01 01 89 4d 90 01 01 8b 4d 90 01 01 39 c8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc 90 02 0a cc 90 02 0a cc 90 00 } //02 00 
		$a_80_1 = {6c 6c 6f 73 65 77 77 71 2e 6c 6c } //llosewwq.ll  02 00 
		$a_80_2 = {2e 70 64 62 } //.pdb  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_3{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {c7 44 24 08 0e 00 00 00 90 02 08 89 4c 24 90 02 0a e8 90 00 } //0a 00 
		$a_02_1 = {cc cc 40 cc eb 90 01 01 8b 04 24 64 a3 00 00 00 00 83 c4 08 eb 90 01 01 8b 44 24 90 01 01 ff 80 90 01 04 31 c0 c3 c3 90 00 } //0a 00 
		$a_80_2 = {74 74 74 74 33 32 } //tttt32  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 90 02 28 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 53 00 cc 90 02 0c cc 90 02 0c cc 90 00 } //02 00 
		$a_80_1 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  02 00 
		$a_80_2 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  02 00 
		$a_80_3 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  02 00 
		$a_80_4 = {66 66 74 79 2e 70 64 62 } //ffty.pdb  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_5{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 03 00 00 0a 00 "
		
	strings :
		$a_02_0 = {69 88 b4 24 90 01 04 c6 84 24 90 01 04 74 c6 84 24 90 01 04 75 c6 84 24 90 01 04 61 c6 84 24 90 01 04 6c 8b 84 24 90 01 04 35 90 01 04 c6 84 24 90 01 04 41 90 00 } //0a 00 
		$a_02_1 = {4c 00 64 00 72 00 47 00 65 00 74 00 50 00 72 00 6f 00 63 00 65 00 64 00 75 00 72 00 65 00 41 00 90 01 10 79 00 90 00 } //0a 00 
		$a_02_2 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 90 01 10 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_6{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 90 02 14 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc 90 02 0c cc 90 02 0c cc 90 00 } //02 00 
		$a_80_1 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  02 00 
		$a_80_2 = {52 54 54 59 45 42 48 55 59 2e 70 64 62 } //RTTYEBHUY.pdb  02 00 
		$a_80_3 = {4d 61 6e 79 76 76 65 72 73 69 6f 6e 6e 64 61 69 6c 79 6b 4c 69 74 6f 72 61 6e 69 6d 61 6c } //ManyvversionndailykLitoranimal  02 00 
		$a_80_4 = {67 67 70 6c 6f 65 45 52 2e 64 6c 6c } //ggploeER.dll  00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_GC_MTB_7{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 07 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 04 24 64 a3 00 00 00 00 90 02 0f 83 c4 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc 90 02 0a cc 90 02 0a cc 90 00 } //0a 00 
		$a_02_1 = {8b 04 24 64 a3 00 00 00 00 90 02 0f 83 ec 04 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc 90 02 0a cc 90 02 0a cc 90 00 } //0a 00 
		$a_02_2 = {8b 04 24 64 a3 00 00 00 00 90 02 0f 83 ec 08 eb 0d 8b 44 24 0c ff 80 b8 00 00 00 31 c0 c3 c3 90 0a 4b 00 cc 90 02 0a cc 90 02 0a cc 90 00 } //02 00 
		$a_80_3 = {62 42 4f 4c 4c 50 49 55 } //bBOLLPIU  02 00 
		$a_80_4 = {67 70 6f 69 72 65 65 } //gpoiree  02 00 
		$a_80_5 = {46 47 74 6b 65 6d 76 62 } //FGtkemvb  02 00 
		$a_80_6 = {2e 70 64 62 } //.pdb  00 00 
	condition:
		any of ($a_*)
 
}