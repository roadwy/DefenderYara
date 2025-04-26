
rule Trojan_BAT_SpySnake_MG_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 9a 1f 10 28 ?? ?? ?? 0a 9c 09 17 d6 0d 00 09 07 8e 69 fe 04 13 05 11 05 2d e2 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}
rule Trojan_BAT_SpySnake_MG_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 6d 00 00 00 19 00 00 00 b4 00 00 00 bd } //10
		$a_01_1 = {37 35 39 31 32 33 34 37 2d 62 32 37 63 2d 34 61 63 31 2d 38 37 35 36 2d 31 64 61 65 66 66 33 30 34 64 38 } //10 75912347-b27c-4ac1-8756-1daeff304d8
		$a_01_2 = {65 61 74 53 6f 6d 65 74 68 69 6e 67 } //1 eatSomething
		$a_01_3 = {42 30 32 30 33 32 30 34 } //1 B0203204
		$a_01_4 = {44 35 32 38 34 37 33 35 32 33 34 35 } //1 D52847352345
		$a_01_5 = {45 76 6f 6c 75 74 69 6f 6e 5f 53 69 6d 75 6c 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Evolution_Simulation.Properties
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=24
 
}
rule Trojan_BAT_SpySnake_MG_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {54 45 4d 50 5c 6e 73 64 32 38 42 44 2e 74 6d 70 5c 77 66 66 67 2e 64 6c 6c } //1 TEMP\nsd28BD.tmp\wffg.dll
		$a_01_1 = {76 61 6e 71 75 69 73 68 69 6e 67 5c 62 69 74 73 79 2e 65 78 65 } //1 vanquishing\bitsy.exe
		$a_01_2 = {64 69 73 67 75 73 74 5c 69 72 6f 6e 69 6e 67 2e 62 61 74 } //1 disgust\ironing.bat
		$a_01_3 = {61 64 6d 6f 6e 69 73 68 5c 67 6c 69 74 74 65 72 69 6e 67 2e 62 61 74 } //1 admonish\glittering.bat
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 70 6f 72 74 69 6f 6e 73 5c 6d 61 72 6d 61 6c 61 64 65 } //1 SOFTWARE\portions\marmalade
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 69 6e 74 69 6d 61 63 79 } //1 SOFTWARE\intimacy
		$a_01_6 = {53 6c 65 65 70 } //1 Sleep
		$a_01_7 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}