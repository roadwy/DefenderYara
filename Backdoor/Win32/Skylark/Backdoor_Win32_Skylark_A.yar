
rule Backdoor_Win32_Skylark_A{
	meta:
		description = "Backdoor:Win32/Skylark.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 6b 79 6c 61 72 6b 20 53 65 72 76 65 72 20 76 } //4 Skylark Server v
		$a_01_1 = {54 72 6f 6a 61 6e 20 4d 61 6e 61 67 65 6d 65 6e 74 20 41 67 65 6e 74 73 20 4d 6f 64 75 6c 65 2e } //3 Trojan Management Agents Module.
		$a_01_2 = {53 6b 79 6c 61 72 6b 43 66 67 } //4 SkylarkCfg
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*4) >=11
 
}