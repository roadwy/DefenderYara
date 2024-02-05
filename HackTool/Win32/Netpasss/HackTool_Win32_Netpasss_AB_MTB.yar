
rule HackTool_Win32_Netpasss_AB_MTB{
	meta:
		description = "HackTool:Win32/Netpasss.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {57 4e 65 74 45 6e 75 6d 43 61 63 68 65 64 50 61 73 73 77 6f 72 64 73 } //WNetEnumCachedPasswords  01 00 
		$a_80_1 = {6e 69 72 73 6f 66 74 2e 6e 65 74 } //nirsoft.net  01 00 
		$a_80_2 = {45 78 70 6f 72 74 20 52 61 77 20 50 61 73 73 77 6f 72 64 73 20 44 61 74 61 } //Export Raw Passwords Data  01 00 
		$a_80_3 = {4e 65 74 77 6f 72 6b 20 50 61 73 73 77 6f 72 64 20 52 65 63 6f 76 65 72 79 } //Network Password Recovery  01 00 
		$a_80_4 = {4e 65 74 77 6f 72 6b 20 50 61 73 73 77 6f 72 64 73 20 4c 69 73 74 } //Network Passwords List  00 00 
	condition:
		any of ($a_*)
 
}