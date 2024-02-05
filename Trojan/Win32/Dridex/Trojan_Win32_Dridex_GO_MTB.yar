
rule Trojan_Win32_Dridex_GO_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_80_0 = {52 46 46 47 54 45 51 2e 70 64 62 } //RFFGTEQ.pdb  01 00 
		$a_80_1 = {71 6f 65 6e 77 6f 69 64 65 72 64 2e 64 6c 6c } //qoenwoiderd.dll  01 00 
		$a_80_2 = {4c 64 72 47 65 74 50 72 6f 63 65 64 75 72 65 41 } //LdrGetProcedureA  01 00 
		$a_80_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  01 00 
		$a_80_4 = {44 66 6f 65 72 46 6f 70 71 77 64 66 72 73 } //DfoerFopqwdfrs  00 00 
	condition:
		any of ($a_*)
 
}