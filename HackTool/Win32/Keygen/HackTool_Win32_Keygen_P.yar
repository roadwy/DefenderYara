
rule HackTool_Win32_Keygen_P{
	meta:
		description = "HackTool:Win32/Keygen.P,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {be 0c a2 40 00 8d 7d 80 f3 a5 8d 45 b4 50 ff 75 08 a4 } //01 00 
		$a_01_1 = {5c 6e 65 72 6f 38 78 5c 52 65 6c 65 61 73 65 5c 6b 65 79 67 65 6e 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}