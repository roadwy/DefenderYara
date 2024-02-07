
rule HackTool_Linux_MSFPythonShell_A{
	meta:
		description = "HackTool:Linux/MSFPythonShell.A,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {70 00 79 00 74 00 68 00 6f 00 6e 00 } //01 00  python
		$a_00_1 = {65 00 78 00 65 00 63 00 28 00 62 00 61 00 73 00 65 00 36 00 34 00 2e 00 62 00 36 00 34 00 64 00 65 00 63 00 6f 00 64 00 65 00 } //01 00  exec(base64.b64decode
		$a_00_2 = {7b 00 32 00 3a 00 73 00 74 00 72 00 2c 00 33 00 3a 00 6c 00 61 00 6d 00 62 00 64 00 61 00 20 00 62 00 3a 00 62 00 79 00 74 00 65 00 73 00 } //01 00  {2:str,3:lambda b:bytes
		$a_00_3 = {5b 00 73 00 79 00 73 00 2e 00 76 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5f 00 69 00 6e 00 66 00 6f 00 5b 00 30 00 5d 00 5d 00 } //00 00  [sys.version_info[0]]
	condition:
		any of ($a_*)
 
}