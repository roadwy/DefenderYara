
rule Trojan_Win32_Dridex_SBB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.SBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {73 75 63 63 65 73 73 2e 70 64 62 } //success.pdb  3
		$a_80_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  3
		$a_80_2 = {70 70 70 70 31 31 31 31 66 66 66 66 } //pppp1111ffff  3
		$a_80_3 = {57 72 69 74 65 43 6f 6e 73 6f 6c 65 57 } //WriteConsoleW  3
		$a_80_4 = {46 6c 75 73 68 46 69 6c 65 42 75 66 66 65 72 73 } //FlushFileBuffers  3
		$a_80_5 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //DllRegisterServer  3
		$a_80_6 = {50 6f 73 74 4d 65 73 73 61 67 65 41 } //PostMessageA  3
		$a_80_7 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //CallNextHookEx  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}
rule Trojan_Win32_Dridex_SBB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.SBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_80_0 = {66 70 6e 2e 70 64 62 } //fpn.pdb  3
		$a_80_1 = {44 65 6c 65 74 65 53 65 63 75 72 69 74 79 43 6f 6e 74 65 78 74 } //DeleteSecurityContext  3
		$a_80_2 = {6b 65 72 6e 65 6c 33 32 2e 53 6c 65 65 70 } //kernel32.Sleep  3
		$a_80_3 = {52 65 67 4f 76 65 72 72 69 64 65 50 72 65 64 65 66 4b 65 79 } //RegOverridePredefKey  3
		$a_80_4 = {2c 73 79 73 74 65 6d 2e 31 39 32 45 36 36 36 36 36 36 70 72 6f 63 65 73 73 65 73 5a 73 65 63 75 72 69 74 79 } //,system.192E666666processesZsecurity  3
		$a_80_5 = {77 32 6a 63 6f 6e 6e 65 63 74 65 64 64 77 69 74 68 77 33 2c 6f 6e 63 65 } //w2jconnecteddwithw3,once  3
		$a_80_6 = {6d 64 65 63 6f 64 69 6e 67 2e 31 35 30 73 6c 61 79 65 72 6b 77 69 74 68 34 6f 6e 31 } //mdecoding.150slayerkwith4on1  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3) >=21
 
}