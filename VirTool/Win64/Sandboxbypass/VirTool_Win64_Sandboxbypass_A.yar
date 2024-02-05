
rule VirTool_Win64_Sandboxbypass_A{
	meta:
		description = "VirTool:Win64/Sandboxbypass.A,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 c7 c1 02 00 00 00 ff 15 90 01 02 00 00 48 8b c8 48 c7 c2 02 00 00 00 48 83 ec 30 49 c7 c0 00 10 00 00 4c 89 44 24 20 4d 33 c0 4d 8b c8 ff 15 90 01 02 00 00 48 8b 4d f8 48 89 08 48 33 c9 ff 15 90 01 02 00 00 90 02 05 69 65 66 72 61 6d 65 2e 64 6c 6c 00 66 6d 36 34 90 00 } //00 00 
		$a_00_1 = {5d } //04 00 
	condition:
		any of ($a_*)
 
}