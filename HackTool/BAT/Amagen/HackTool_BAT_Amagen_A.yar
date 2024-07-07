
rule HackTool_BAT_Amagen_A{
	meta:
		description = "HackTool:BAT/Amagen.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 6d 61 7a 6f 6e 20 52 65 63 65 69 70 74 20 47 65 6e 65 72 61 74 6f 72 } //1 Amazon Receipt Generator
		$a_02_1 = {50 6c 65 61 73 65 20 6d 61 6b 65 20 73 75 72 65 20 74 6f 20 76 69 73 69 74 20 6f 75 72 20 73 69 74 65 20 61 6e 64 20 73 69 67 6e 20 75 70 20 66 6f 72 20 6d 6f 72 65 90 02 04 62 6f 74 73 20 6c 69 6b 65 20 74 68 69 73 20 6f 6e 65 90 00 } //1
		$a_00_2 = {54 68 65 20 6f 72 64 65 72 20 6e 75 6d 62 65 72 20 69 73 20 74 68 65 20 6e 75 6d 62 65 72 20 74 68 61 74 20 77 69 6c 6c 20 62 65 20 67 65 6e 65 72 61 74 65 64 } //1 The order number is the number that will be generated
		$a_00_3 = {42 6f 74 74 69 6e 67 20 57 6f 72 6c 64 } //1 Botting World
		$a_00_4 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 } //1 System.Runtime.CompilerServices
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}