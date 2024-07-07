
rule Trojan_BAT_Perseus_NE_MTB{
	meta:
		description = "Trojan:BAT/Perseus.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 "
		
	strings :
		$a_01_0 = {62 31 31 36 31 39 63 61 34 64 36 36 63 65 65 62 35 39 63 37 63 35 66 62 38 65 38 65 37 33 38 64 } //5 b11619ca4d66ceeb59c7c5fb8e8e738d
		$a_01_1 = {43 61 6c 20 53 74 65 72 65 6f } //5 Cal Stereo
		$a_01_2 = {67 65 74 5f 5f 36 64 38 37 32 39 35 } //5 get__6d87295
		$a_01_3 = {41 64 6d 69 6e 69 73 74 72 61 74 69 76 65 20 70 72 6f 6a 65 63 74 20 63 6f 6f 72 64 69 6e 61 74 6f 72 } //5 Administrative project coordinator
		$a_01_4 = {4d 6f 74 6f 72 20 56 65 68 69 63 6c 65 20 4d 61 6e 75 66 61 63 74 75 72 69 6e 67 } //5 Motor Vehicle Manufacturing
		$a_01_5 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //1 IsDebuggerPresent
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5+(#a_01_4  & 1)*5+(#a_01_5  & 1)*1) >=26
 
}