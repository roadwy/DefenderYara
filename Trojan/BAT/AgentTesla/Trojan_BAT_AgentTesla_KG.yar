
rule Trojan_BAT_AgentTesla_KG{
	meta:
		description = "Trojan:BAT/AgentTesla.KG,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 13 00 00 05 00 "
		
	strings :
		$a_01_0 = {02 1f 20 03 59 1f 1f 5f 64 02 03 1f 1f 5f 62 60 2a } //05 00 
		$a_03_1 = {02 03 02 4b 03 05 5f 04 05 66 5f 60 58 0e 07 0e 04 e0 95 58 7e 90 01 04 0e 06 17 59 e0 95 58 0e 05 28 90 00 } //03 00 
		$a_00_2 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } //01 00  WindowsFormsApp
		$a_00_3 = {4c 69 73 74 5f 6f 6d 64 72 65 2e 65 78 65 } //01 00  List_omdre.exe
		$a_00_4 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 31 30 2d 31 } //01 00  $$method0x6000010-1
		$a_00_5 = {35 72 35 6f 75 64 } //01 00  5r5oud
		$a_00_6 = {4c 69 6d 65 5f 41 73 79 6e 63 43 6c 69 65 6e 74 53 70 6f 6f 66 65 72 } //01 00  Lime_AsyncClientSpoofer
		$a_00_7 = {4c 69 6d 65 5f 41 73 79 6e 63 43 6c 69 65 6e 74 53 70 6f 6f 66 65 72 2e 65 78 65 } //01 00  Lime_AsyncClientSpoofer.exe
		$a_00_8 = {4c 69 6d 65 5f 41 73 79 6e 63 43 6c 69 65 6e 74 53 70 6f 6f 66 65 72 2e 43 6f 6e 73 75 6d 65 72 73 } //01 00  Lime_AsyncClientSpoofer.Consumers
		$a_00_9 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 33 64 2d 31 } //01 00  $$method0x600003d-1
		$a_00_10 = {62 69 74 63 6c 69 65 6e 74 31 2e 65 78 65 } //01 00  bitclient1.exe
		$a_00_11 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 36 35 2d 31 } //01 00  $$method0x6000065-1
		$a_00_12 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 37 36 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  WindowsFormsApp76.Properties
		$a_00_13 = {4c 69 6d 65 5f 61 73 79 6e 63 2e 44 65 66 69 6e 69 74 69 6f 6e 73 } //01 00  Lime_async.Definitions
		$a_00_14 = {43 61 6c 63 53 63 68 65 6d 61 } //01 00  CalcSchema
		$a_00_15 = {4c 69 6d 65 5f 61 73 79 6e 63 2e 53 70 65 63 69 66 69 63 61 74 69 6f 6e 73 } //01 00  Lime_async.Specifications
		$a_00_16 = {4c 69 6d 65 5f 41 67 65 6e 74 } //01 00  Lime_Agent
		$a_00_17 = {4c 69 6d 65 5f 41 67 65 6e 74 2e 65 78 65 } //01 00  Lime_Agent.exe
		$a_00_18 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 31 63 2d 31 } //00 00  $$method0x600001c-1
		$a_00_19 = {5d 04 00 00 a9 40 04 80 5c 2b 00 00 aa } //40 04 
	condition:
		any of ($a_*)
 
}