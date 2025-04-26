
rule HackTool_Win32_InstallWimTweak_A{
	meta:
		description = "HackTool:Win32/InstallWimTweak.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_80_0 = {69 6e 73 74 61 6c 6c 5f 77 69 6d 5f 74 77 65 61 6b 2e 70 64 62 } //install_wim_tweak.pdb  1
		$a_80_1 = {69 6e 73 74 61 6c 6c 5f 77 69 6d 5f 74 77 65 61 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //install_wim_tweak.Properties.Resources.resources  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=1
 
}