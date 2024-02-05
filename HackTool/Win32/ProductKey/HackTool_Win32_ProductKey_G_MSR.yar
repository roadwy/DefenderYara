
rule HackTool_Win32_ProductKey_G_MSR{
	meta:
		description = "HackTool:Win32/ProductKey.G!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {7a 3a 5c 50 72 6f 6a 65 63 74 73 5c 56 53 32 30 30 35 5c 50 72 6f 64 75 4b 65 79 5c 52 65 6c 65 61 73 65 5c 50 72 6f 64 75 4b 65 79 2e 70 64 62 } //01 00 
		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 4e 69 72 53 6f 66 74 5c 50 72 6f 64 75 4b 65 79 } //01 00 
		$a_01_2 = {24 24 50 52 4f 44 55 43 4b 45 59 5f 54 45 4d 50 5f 48 49 56 45 24 24 } //01 00 
		$a_01_3 = {50 72 6f 64 75 63 74 20 6b 65 79 20 77 61 73 20 6e 6f 74 20 66 6f 75 6e 64 } //00 00 
	condition:
		any of ($a_*)
 
}