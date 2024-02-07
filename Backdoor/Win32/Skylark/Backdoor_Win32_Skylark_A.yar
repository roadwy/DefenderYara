
rule Backdoor_Win32_Skylark_A{
	meta:
		description = "Backdoor:Win32/Skylark.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 04 00 "
		
	strings :
		$a_01_0 = {53 6b 79 6c 61 72 6b 20 53 65 72 76 65 72 20 76 } //03 00  Skylark Server v
		$a_01_1 = {54 72 6f 6a 61 6e 20 4d 61 6e 61 67 65 6d 65 6e 74 20 41 67 65 6e 74 73 20 4d 6f 64 75 6c 65 2e } //04 00  Trojan Management Agents Module.
		$a_01_2 = {53 6b 79 6c 61 72 6b 43 66 67 } //00 00  SkylarkCfg
	condition:
		any of ($a_*)
 
}