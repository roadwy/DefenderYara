
rule HackTool_BAT_Stracciatella_AMTB{
	meta:
		description = "HackTool:BAT/Stracciatella!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {44 69 73 61 62 6c 65 53 63 72 69 70 74 4c 6f 67 67 69 6e 67 54 65 63 68 6e 69 71 75 65 31 } //DisableScriptLoggingTechnique1  1
		$a_80_1 = {44 69 73 61 62 6c 65 41 6d 73 69 54 65 63 68 6e 69 71 75 65 } //DisableAmsiTechnique  1
		$a_80_2 = {53 74 72 61 63 63 69 61 74 65 6c 6c 61 2e 70 64 62 } //Stracciatella.pdb  1
		$a_80_3 = {50 6f 77 65 72 73 68 65 6c 6c 20 72 75 6e 73 70 61 63 65 20 77 69 74 68 20 41 4d 53 49 20 61 6e 64 20 53 63 72 69 70 74 20 42 6c 6f 63 6b 20 4c 6f 67 67 69 6e 67 20 64 69 73 61 62 6c 65 64 2e } //Powershell runspace with AMSI and Script Block Logging disabled.  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}