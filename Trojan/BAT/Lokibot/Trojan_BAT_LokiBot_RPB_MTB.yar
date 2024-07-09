
rule Trojan_BAT_LokiBot_RPB_MTB{
	meta:
		description = "Trojan:BAT/LokiBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 07 07 11 07 9a 1f 10 28 b2 00 00 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } //1
		$a_01_1 = {4d 00 61 00 67 00 69 00 63 00 55 00 49 00 2e 00 47 00 52 00 45 00 45 00 4e 00 } //1 MagicUI.GREEN
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_LokiBot_RPB_MTB_2{
	meta:
		description = "Trojan:BAT/LokiBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 00 08 09 16 20 00 10 00 00 6f ca 00 00 0a 13 05 11 05 16 fe 02 13 06 11 06 2c 0e 00 11 04 09 16 11 05 6f cb 00 00 0a 00 00 00 11 05 16 fe 02 13 07 11 07 2d cb } //1
		$a_01_1 = {43 6f 6d 70 69 6c 61 74 69 6f 6e 52 65 6c 61 78 61 74 69 6f 6e 73 } //1 CompilationRelaxations
		$a_01_2 = {43 61 74 65 67 6f 72 79 4d 65 6d 62 65 72 73 68 69 70 } //1 CategoryMembership
		$a_01_3 = {44 65 66 65 72 72 65 64 44 69 73 70 6f 73 61 62 6c 65 } //1 DeferredDisposable
		$a_01_4 = {53 63 68 65 64 75 6c 65 64 43 6f 6e 63 75 72 72 65 6e 74 } //1 ScheduledConcurrent
		$a_01_5 = {36 00 35 00 37 00 33 00 36 00 43 00 } //1 65736C
		$a_01_6 = {49 00 6e 00 66 00 75 00 73 00 69 00 6f 00 6e 00 } //1 Infusion
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_BAT_LokiBot_RPB_MTB_3{
	meta:
		description = "Trojan:BAT/LokiBot.RPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 [0-80] 2e 00 70 00 6e 00 67 00 } //1
		$a_01_1 = {4b 00 71 00 71 00 67 00 76 00 6f 00 6b 00 6b 00 73 00 7a 00 6d 00 77 00 6f 00 73 00 6f 00 62 00 72 00 77 00 67 00 69 00 77 00 6f 00 68 00 } //1 Kqqgvokkszmwosobrwgiwoh
		$a_01_2 = {47 6f 6c 64 65 6e 20 46 72 6f 67 } //1 Golden Frog
		$a_01_3 = {54 6f 41 72 72 61 79 } //1 ToArray
		$a_01_4 = {57 65 62 52 65 71 75 65 73 74 } //1 WebRequest
		$a_01_5 = {47 65 74 42 79 74 65 73 } //1 GetBytes
		$a_01_6 = {45 6e 63 6f 64 69 6e 67 } //1 Encoding
		$a_01_7 = {47 65 74 54 79 70 65 } //1 GetType
		$a_01_8 = {44 79 6e 61 6d 69 63 49 6e 76 6f 6b 65 } //1 DynamicInvoke
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}