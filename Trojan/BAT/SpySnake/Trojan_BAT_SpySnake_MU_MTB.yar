
rule Trojan_BAT_SpySnake_MU_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 0a 00 "
		
	strings :
		$a_01_0 = {0a 02 8e 69 18 5a 06 8e 69 58 0b 2b 3d 00 02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 } //05 00 
		$a_01_1 = {4b 6c 69 65 6e 74 20 64 6f 20 62 6c 69 70 61 } //05 00  Klient do blipa
		$a_01_2 = {42 6c 69 70 46 61 63 65 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  BlipFace.Properties
		$a_01_3 = {68 6f 74 6b 65 79 5f 48 6f 74 6b 65 79 50 72 65 73 73 65 64 } //00 00  hotkey_HotkeyPressed
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MU_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 05 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 99 00 00 00 11 00 00 00 98 00 00 00 81 00 00 00 ab 00 00 00 6b 01 00 00 18 } //05 00 
		$a_01_1 = {4a 61 6d 62 6f } //05 00  Jambo
		$a_01_2 = {63 31 32 31 62 35 66 35 2d 33 32 62 63 2d 34 65 32 64 2d 39 62 38 63 2d 61 61 64 37 31 65 64 37 34 64 37 66 } //05 00  c121b5f5-32bc-4e2d-9b8c-aad71ed74d7f
		$a_01_3 = {53 74 6f 63 6b 50 6c 6f 74 2e 50 72 6f 70 65 72 74 69 65 73 } //01 00  StockPlot.Properties
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MU_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 76 65 72 73 65 } //01 00  Reverse
		$a_01_1 = {54 6f 41 72 72 61 79 } //01 00  ToArray
		$a_03_2 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 90 02 60 2e 00 70 00 6e 00 67 00 90 00 } //01 00 
		$a_01_3 = {44 65 6c 61 70 65 64 4c 6f 6f 70 } //01 00  DelapedLoop
		$a_01_4 = {53 6c 65 65 70 } //01 00  Sleep
		$a_01_5 = {48 00 69 00 64 00 64 00 65 00 6e 00 20 00 52 00 65 00 66 00 6c 00 65 00 78 00 20 00 41 00 75 00 74 00 68 00 6f 00 72 00 73 00 } //01 00  Hidden Reflex Authors
		$a_01_6 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_01_7 = {4e 00 72 00 6a 00 6c 00 73 00 6b 00 } //00 00  Nrjlsk
	condition:
		any of ($a_*)
 
}