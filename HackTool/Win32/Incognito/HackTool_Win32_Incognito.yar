
rule HackTool_Win32_Incognito{
	meta:
		description = "HackTool:Win32/Incognito,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 2a 5d 20 41 74 74 65 6d 70 74 69 6e 67 20 74 6f 20 61 64 64 20 75 73 65 72 20 25 73 20 74 6f 20 67 72 6f 75 70 20 25 73 20 6f 6e 20 64 6f 6d 61 69 6e 20 63 6f 6e 74 72 6f 6c 6c 65 72 20 25 73 0a 00 } //01 00 
		$a_01_1 = {5b 2b 5d 20 53 75 63 63 65 73 73 66 75 6c 6c 79 20 61 64 64 65 64 20 75 73 65 72 20 74 6f 20 67 72 6f 75 70 0a 00 } //01 00 
		$a_01_2 = {69 6e 63 6f 67 6e 69 74 6f } //00 00  incognito
	condition:
		any of ($a_*)
 
}