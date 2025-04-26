
rule Backdoor_Win32_Farfli_GNL_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.GNL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 41 b3 6c 68 ?? ?? ?? ?? 51 88 44 24 ?? c6 44 24 ?? 44 c6 44 24 ?? 56 88 44 24 ?? c6 44 24 ?? 50 c6 44 24 ?? 49 c6 44 24 ?? 33 c6 44 24 ?? 32 c6 44 24 ?? 2e c6 44 24 ?? 64 88 5c 24 ?? 88 5c 24 ?? c6 44 24 } //10
		$a_01_1 = {50 6c 75 67 69 6e 4d 65 31 } //1 PluginMe1
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}