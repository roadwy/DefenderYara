
rule Backdoor_Win32_ShadowHammer_C_dha{
	meta:
		description = "Backdoor:Win32/ShadowHammer.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 3a 5c 43 2b 2b 5c 41 73 75 73 53 68 65 6c 6c 43 6f 64 65 5c 52 65 6c 65 61 73 65 5c 41 73 75 73 53 68 65 6c 6c 43 6f 64 65 2e 70 64 62 } //10 D:\C++\AsusShellCode\Release\AsusShellCode.pdb
	condition:
		((#a_01_0  & 1)*10) >=10
 
}