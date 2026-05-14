
rule Trojan_Win64_StealC_MCP_MTB{
	meta:
		description = "Trojan:Win64/StealC.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 20 49 44 3a 20 22 66 71 4a 55 75 65 52 30 6c 76 69 41 51 59 64 44 53 6e 69 6d 2f 79 79 68 74 61 4b 45 69 5a 70 52 2d 67 50 6b 37 59 49 65 52 2f 50 4c 43 6b 4f 32 72 50 46 70 48 49 77 46 73 70 32 77 78 } //1 d ID: "fqJUueR0lviAQYdDSnim/yyhtaKEiZpR-gPk7YIeR/PLCkO2rPFpHIwFsp2wx
		$a_01_1 = {44 3a 20 22 4f 32 59 65 36 42 64 39 4f 34 76 67 4f 78 72 4c 43 59 47 44 2f 6a 31 66 66 4c 33 68 44 34 30 46 61 62 44 76 73 35 47 33 6e 2f 6f 66 32 63 59 } //1 D: "O2Ye6Bd9O4vgOxrLCYGD/j1ffL3hD40FabDvs5G3n/of2cY
		$a_01_2 = {49 44 3a 20 22 47 45 6c 4d 6c 76 51 4e 63 4c 41 31 46 34 54 43 4a 6c 35 45 2f 73 62 78 57 4b 57 79 42 79 45 4a 31 68 75 46 61 30 48 4d 59 2f 67 6f 56 73 4b 32 56 50 43 72 39 51 69 57 34 7a 4b 44 31 74 2f } //1 ID: "GElMlvQNcLA1F4TCJl5E/sbxWKWyByEJ1huFa0HMY/goVsK2VPCr9QiW4zKD1t/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}