
rule Trojan_BAT_AgentTesla_GK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {50 75 6e 6b 74 65 45 64 69 74 69 65 72 65 6e 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 PunkteEditierenToolStripMenuItem
		$a_81_1 = {42 61 6e 67 75 6e 52 75 61 6e 67 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 BangunRuangToolStripMenuItem
		$a_81_2 = {4c 69 6e 67 6b 61 72 61 6e 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 LingkaranToolStripMenuItem
		$a_81_3 = {41 6e 75 74 69 61 73 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 AnutiasToolStripMenuItem
		$a_81_4 = {53 69 73 69 70 61 6e 54 6f 6f 6c 53 74 72 69 70 4d 65 6e 75 49 74 65 6d } //1 SisipanToolStripMenuItem
		$a_81_5 = {4c 65 67 74 20 66 65 73 74 2c 20 77 65 6c 63 68 65 20 46 61 72 62 65 20 64 69 65 20 42 65 73 63 68 72 69 66 74 75 6e 67 20 68 61 62 65 6e } //1 Legt fest, welche Farbe die Beschriftung haben
		$a_81_6 = {64 69 65 20 4b 72 65 75 7a 65 20 73 65 69 6e 20 73 6f 6c 6c 65 6e } //1 die Kreuze sein sollen
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_BAT_AgentTesla_GK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 0c 00 00 "
		
	strings :
		$a_81_0 = {24 61 32 31 34 32 30 32 62 2d 38 36 30 35 2d 34 33 66 62 2d 61 30 64 34 2d 32 38 33 33 31 38 34 62 36 34 30 61 } //20 $a214202b-8605-43fb-a0d4-2833184b640a
		$a_81_1 = {24 33 66 32 64 38 61 64 61 2d 61 61 31 35 2d 34 30 65 61 2d 62 39 37 63 2d 38 34 30 63 65 37 30 34 65 37 30 36 } //20 $3f2d8ada-aa15-40ea-b97c-840ce704e706
		$a_81_2 = {24 62 38 37 65 62 31 33 31 2d 33 34 63 65 2d 34 35 36 61 2d 38 30 33 38 2d 62 32 31 35 34 37 33 65 62 66 66 64 } //20 $b87eb131-34ce-456a-8038-b215473ebffd
		$a_81_3 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
		$a_81_4 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerBrowsableAttribute
		$a_81_5 = {44 65 62 75 67 67 65 72 53 74 65 70 54 68 72 6f 75 67 68 41 74 74 72 69 62 75 74 65 } //1 DebuggerStepThroughAttribute
		$a_81_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_81_7 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_81_8 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_9 = {41 63 74 69 76 61 74 6f 72 } //1 Activator
		$a_81_10 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_11 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*20+(#a_81_2  & 1)*20+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1+(#a_81_10  & 1)*1+(#a_81_11  & 1)*1) >=23
 
}
rule Trojan_BAT_AgentTesla_GK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.GK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 49 6e 76 6f 6b 65 4d 65 6d 62 65 72 00 4c 61 74 65 47 65 74 00 43 6f 6d 70 61 72 65 45 78 63 68 61 6e 67 65 00 53 75 62 74 72 61 63 74 } //1
		$a_01_1 = {51 71 56 54 } //1 QqVT
		$a_01_2 = {80 eb a6 84 ec a7 80 45 eb a6 84 ec a7 80 eb a6 84 ec a7 80 4d eb a6 84 ec a7 80 51 71 56 54 40 } //2
		$a_01_3 = {eb a6 84 ec a7 80 eb a6 84 ec a7 } //1
		$a_01_4 = {44 65 6c 74 61 45 6e 67 69 6e 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 DeltaEngine.Properties.Resources.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}