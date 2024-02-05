
rule HackTool_Win32_DisableAmsi{
	meta:
		description = "HackTool:Win32/DisableAmsi,SIGNATURE_TYPE_PEHSTR,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 55 73 65 72 73 5c 61 6e 64 72 65 5c 73 6f 75 72 63 65 5c 72 65 70 6f 73 5c 42 79 70 61 73 73 41 4d 53 49 5c 42 79 70 61 73 73 41 4d 53 49 5c 6f 62 6a 5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 41 4d 53 49 2e 70 64 62 00 } //00 00 
	condition:
		any of ($a_*)
 
}