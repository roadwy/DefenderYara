
rule HackTool_Win32_Cachedump_dha{
	meta:
		description = "HackTool:Win32/Cachedump!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 70 69 70 65 5c 63 61 63 68 65 64 75 6d 70 70 69 70 65 } //01 00  \\.\pipe\cachedumppipe
		$a_00_1 = {53 45 43 55 52 49 54 59 5c 50 6f 6c 69 63 79 5c 53 65 63 72 65 74 73 5c 4e 4c 24 4b 4d 5c 43 75 72 72 56 61 6c } //01 00  SECURITY\Policy\Secrets\NL$KM\CurrVal
		$a_01_2 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 20 53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 30 35 } //01 00  GetProcAddress SystemFunction005
		$a_00_3 = {4c 53 41 20 43 69 70 68 65 72 20 4b 65 79 20 62 79 20 52 65 67 4f 70 65 6e 4b 65 79 45 78 } //00 00  LSA Cipher Key by RegOpenKeyEx
		$a_00_4 = {5d 04 00 00 } //9a 36 
	condition:
		any of ($a_*)
 
}