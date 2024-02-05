
rule VirTool_Win32_Obfuscator_AKE{
	meta:
		description = "VirTool:Win32/Obfuscator.AKE,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {55 00 6e 00 69 00 78 00 20 00 66 00 69 00 6c 00 65 00 20 00 64 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 74 00 61 00 72 00 67 00 65 00 74 00 6a 00 6f 00 62 00 00 00 5c 5c 76 6d 77 61 72 65 2d 68 6f 73 74 3a 59 20 00 00 00 00 44 6f 6d 61 69 6e 42 69 67 53 70 61 63 65 20 72 65 73 75 6c 74 69 69 74 65 6d 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}