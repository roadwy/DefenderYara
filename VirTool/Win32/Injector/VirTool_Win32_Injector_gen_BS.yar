
rule VirTool_Win32_Injector_gen_BS{
	meta:
		description = "VirTool:Win32/Injector.gen!BS,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 57 6f 72 6b 5c 44 50 61 63 6b 65 72 36 34 5c 52 65 6c 65 61 73 65 5c 44 45 78 65 53 74 75 62 33 32 2e 70 64 62 } //00 00  C:\Work\DPacker64\Release\DExeStub32.pdb
	condition:
		any of ($a_*)
 
}