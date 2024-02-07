
rule HackTool_Linux_MSFPythonShell_C{
	meta:
		description = "HackTool:Linux/MSFPythonShell.C,SIGNATURE_TYPE_CMDHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //05 00  python
		$a_01_1 = {65 00 78 00 65 00 63 00 28 00 27 00 61 00 57 00 31 00 77 00 62 00 33 00 4a 00 30 00 49 00 48 00 4e 00 76 00 59 00 32 00 74 00 6c 00 64 00 } //05 00  exec('aW1wb3J0IHNvY2tld
		$a_01_2 = {4c 00 6d 00 4e 00 68 00 62 00 47 00 77 00 6f 00 49 00 69 00 39 00 69 00 61 00 57 00 34 00 76 00 59 00 6d 00 46 00 7a 00 61 00 43 00 49 00 70 00 27 00 2e 00 64 00 65 00 63 00 6f 00 64 00 65 00 28 00 27 00 62 00 61 00 73 00 65 00 36 00 34 00 27 00 29 00 29 00 } //00 00  LmNhbGwoIi9iaW4vYmFzaCIp'.decode('base64'))
	condition:
		any of ($a_*)
 
}