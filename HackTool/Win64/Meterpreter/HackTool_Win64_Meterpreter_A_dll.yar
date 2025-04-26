
rule HackTool_Win64_Meterpreter_A_dll{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 f9 5d 68 fa 3c [0-04] 8b } //1
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_2 = {8e 4e 0e ec [0-04] aa fc 0d 7c } //1
		$a_03_3 = {45 33 c9 48 03 da 48 83 ca ff 45 33 c0 e8 ?? ?? ?? ?? ?? 8b } //1
		$a_03_4 = {ff d3 48 8b c3 48 81 c4 ?? 00 00 00 41 5f 41 5e 41 5d 41 5c 5f 5e 5b 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule HackTool_Win64_Meterpreter_A_dll_2{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //1 刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_2 = {8e 4e 0e ec 74 [0-04] aa fc 0d 7c 74 [0-04] 54 ca af 91 74 [0-04] f2 32 f6 0e 75 } //1
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } //1
		$a_01_4 = {b8 0a 4c 53 75 } //1
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-04] ff d6 } //1
		$a_01_6 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule HackTool_Win64_Meterpreter_A_dll_3{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //1 刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_2 = {8e 4e 0e ec 74 [0-04] aa fc 0d 7c 74 [0-04] 54 ca af 91 74 [0-04] f2 32 f6 0e 75 } //1
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } //1
		$a_01_4 = {b8 0a 4c 53 75 } //1
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-04] ff d6 } //1
		$a_01_6 = {8b 5e 28 45 33 c0 33 d2 48 83 c9 ff 48 03 df ff 54 24 70 45 33 c0 48 8b cf 41 8d 50 01 ff d3 48 8b c3 48 83 c4 28 41 5f 41 5e 41 5d 41 5c 5f 5e 5d 5b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}
rule HackTool_Win64_Meterpreter_A_dll_4{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 f9 5b bc 4a 6a 0f 85 } //1
		$a_03_1 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } //1
		$a_01_2 = {b8 0a 4c 53 75 } //1
		$a_03_3 = {8e 4e 0e ec 74 [0-05] aa fc 0d 7c 74 [0-05] 54 ca af 91 74 [0-05] 1b c6 46 79 [0-05] f2 32 f6 0e 75 } //1
		$a_03_4 = {3c 45 8b cb 33 c9 ?? 03 ?? 41 b8 00 30 00 00 [0-10] ff d6 } //2
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 [0-10] ff d6 } //2
		$a_03_6 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff ?? 03 ?? ff 94 24 88 00 00 00 45 33 c0 ?? 8b ?? 41 8d ?? ?? ff d3 48 8b c3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*1) >=7
 
}