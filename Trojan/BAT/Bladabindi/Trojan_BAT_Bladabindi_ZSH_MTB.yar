
rule Trojan_BAT_Bladabindi_ZSH_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.ZSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_80_0 = {2a 20 57 69 6e 64 6f 77 73 20 62 6c 6f 63 6b 65 64 21 } //* Windows blocked!  1
		$a_80_1 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 21 } //Your files are encrypted!  1
		$a_80_2 = {54 65 6c 65 67 72 61 6d } //Telegram  1
		$a_80_3 = {74 61 73 6b 6b 69 6c 6c 2e 65 78 65 20 2f 69 6d 20 45 78 70 6c 6f 72 65 72 2e 65 78 65 20 2f 66 } //taskkill.exe /im Explorer.exe /f  1
		$a_01_4 = {41 6e 79 52 75 6e 5f 44 65 74 65 63 74 65 64 } //1 AnyRun_Detected
		$a_01_5 = {53 61 6e 64 42 6f 78 5f 44 65 74 65 63 74 65 64 } //1 SandBox_Detected
		$a_01_6 = {44 69 73 61 62 6c 65 53 61 66 65 4d 6f 64 65 } //1 DisableSafeMode
		$a_01_7 = {44 69 73 61 62 6c 65 52 65 67 69 73 74 72 79 } //1 DisableRegistry
		$a_01_8 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 61 6e 61 67 65 72 } //1 DisableTaskManager
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}