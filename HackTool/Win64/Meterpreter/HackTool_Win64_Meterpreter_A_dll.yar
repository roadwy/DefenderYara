
rule HackTool_Win64_Meterpreter_A_dll{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00  刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 02 04 aa fc 0d 7c 74 90 02 04 54 ca af 91 74 90 02 04 f2 32 f6 0e 75 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 04 ff d6 90 00 } //01 00 
		$a_01_6 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win64_Meterpreter_A_dll_2{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } //01 00  刀晥敬瑣癩䱥慯敤r
		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_2 = {8e 4e 0e ec 74 90 02 04 aa fc 0d 7c 74 90 02 04 54 ca af 91 74 90 02 04 f2 32 f6 0e 75 90 00 } //01 00 
		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_4 = {b8 0a 4c 53 75 } //01 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 40 90 02 04 ff d6 90 00 } //01 00 
		$a_01_6 = {8b 5e 28 45 33 c0 33 d2 48 83 c9 ff 48 03 df ff 54 24 70 45 33 c0 48 8b cf 41 8d 50 01 ff d3 48 8b c3 48 83 c4 28 41 5f 41 5e 41 5d 41 5c 5f 5e 5d 5b c3 } //00 00 
	condition:
		any of ($a_*)
 
}
rule HackTool_Win64_Meterpreter_A_dll_3{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {81 f9 5b bc 4a 6a 0f 85 } //01 00 
		$a_03_1 = {81 f9 5d 68 fa 3c 0f 85 90 01 01 00 00 00 90 00 } //01 00 
		$a_01_2 = {b8 0a 4c 53 75 } //01 00 
		$a_03_3 = {8e 4e 0e ec 74 90 02 05 aa fc 0d 7c 74 90 02 05 54 ca af 91 74 90 02 05 1b c6 46 79 90 02 05 f2 32 f6 0e 75 90 00 } //02 00 
		$a_03_4 = {3c 45 8b cb 33 c9 90 01 01 03 90 01 01 41 b8 00 30 00 00 90 02 10 ff d6 90 00 } //02 00 
		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 90 01 01 03 90 01 01 44 8d 49 90 02 10 ff d6 90 00 } //01 00 
		$a_03_6 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 90 01 01 03 90 01 01 ff 94 24 88 00 00 00 45 33 c0 90 01 01 8b 90 01 01 41 8d 90 01 02 ff d3 48 8b c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}