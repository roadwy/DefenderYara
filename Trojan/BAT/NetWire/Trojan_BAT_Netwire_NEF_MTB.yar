
rule Trojan_BAT_Netwire_NEF_MTB{
	meta:
		description = "Trojan:BAT/Netwire.NEF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 0e 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 30 32 62 65 64 66 62 39 2d 63 31 37 33 2d 34 32 33 61 2d 62 30 61 34 2d 64 65 66 35 36 36 38 62 62 64 34 64 } //05 00  $02bedfb9-c173-423a-b0a4-def5668bbd4d
		$a_01_1 = {53 00 75 00 6d 00 6d 00 61 00 72 00 79 00 2e 00 74 00 78 00 74 00 } //05 00  Summary.txt
		$a_01_2 = {53 00 75 00 6d 00 6d 00 61 00 72 00 79 00 2e 00 68 00 74 00 6d 00 } //05 00  Summary.htm
		$a_01_3 = {66 75 7a 7a 79 48 61 73 68 } //05 00  fuzzyHash
		$a_01_4 = {4c 45 4e 47 54 48 53 5f 41 4e 44 5f 4b 49 4e 44 53 } //05 00  LENGTHS_AND_KINDS
		$a_01_5 = {43 4f 4d 50 55 54 45 52 5f 4e 41 4d 45 5f 50 52 4f 50 45 52 54 59 } //05 00  COMPUTER_NAME_PROPERTY
		$a_01_6 = {4d 00 69 00 6e 00 6e 00 65 00 61 00 70 00 6f 00 6c 00 69 00 73 00 } //03 00  Minneapolis
		$a_01_7 = {43 6f 6d 6d 61 6e 64 52 65 61 64 65 72 } //03 00  CommandReader
		$a_01_8 = {43 6f 6e 73 6f 6c 65 43 6c 69 65 6e 74 } //03 00  ConsoleClient
		$a_01_9 = {49 00 6d 00 61 00 67 00 65 00 6d 00 } //03 00  Imagem
		$a_01_10 = {42 72 65 61 6b 44 65 62 75 67 67 65 72 } //01 00  BreakDebugger
		$a_01_11 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //01 00  DebuggerHiddenAttribute
		$a_01_12 = {53 74 61 72 74 75 70 50 61 74 68 } //01 00  StartupPath
		$a_01_13 = {57 61 69 74 42 61 67 } //00 00  WaitBag
	condition:
		any of ($a_*)
 
}