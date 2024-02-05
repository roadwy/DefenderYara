
rule HackTool_BAT_AutoKms{
	meta:
		description = "HackTool:BAT/AutoKms,SIGNATURE_TYPE_PEHSTR,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {26 65 63 68 6f 20 41 63 74 69 76 61 74 69 6e 67 20 4d 69 63 72 6f 73 6f 66 74 20 73 6f 66 74 77 61 72 65 20 70 72 6f 64 75 63 74 73 20 66 6f 72 20 46 52 45 45 26 65 63 68 6f } //02 00 
		$a_01_1 = {69 66 20 25 69 25 3d 3d 31 20 73 65 74 20 4b 4d 53 5f 53 65 76 3d } //02 00 
		$a_01_2 = {63 73 63 72 69 70 74 20 2f 2f 6e 6f 6c 6f 67 6f 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 73 6c 6d 67 72 2e 76 62 73 } //00 00 
	condition:
		any of ($a_*)
 
}