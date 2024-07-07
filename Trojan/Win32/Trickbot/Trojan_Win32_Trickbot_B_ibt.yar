
rule Trojan_Win32_Trickbot_B_ibt{
	meta:
		description = "Trojan:Win32/Trickbot.B!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 0a 00 00 "
		
	strings :
		$a_80_0 = {5c 77 65 62 69 6e 6a 65 63 74 33 32 2e 70 64 62 } //\webinject32.pdb  1
		$a_80_1 = {5c 77 65 62 69 6e 6a 65 63 74 36 32 2e 70 64 62 } //\webinject62.pdb  1
		$a_80_2 = {43 6f 6e 74 72 6f 6c 00 46 72 65 65 42 75 66 66 65 72 00 52 65 6c 65 61 73 65 00 53 74 61 72 74 } //Control  1
		$a_80_3 = {57 65 62 49 6e 6a 65 63 74 20 62 75 69 6c 64 20 25 73 20 25 73 20 28 25 73 29 20 73 74 61 72 74 69 6e 67 } //WebInject build %s %s (%s) starting  1
		$a_80_4 = {53 54 41 54 49 43 20 46 41 4b 45 20 72 65 62 75 69 6c 64 3d } //STATIC FAKE rebuild=  1
		$a_80_5 = {49 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 75 72 65 20 70 72 6f 63 65 73 73 20 70 69 64 20 3d } //Injection failure process pid =  1
		$a_80_6 = {43 68 65 63 6b 41 6e 64 49 6e 6a 65 63 74 45 78 70 6c 6f 72 65 72 28 29 3a 20 43 72 65 61 74 65 54 6f 6f 6c 68 65 6c 70 33 32 53 6e 61 70 73 68 6f 74 28 29 3a } //CheckAndInjectExplorer(): CreateToolhelp32Snapshot():  1
		$a_80_7 = {43 68 72 6f 6d 65 20 69 73 20 7a 6f 6d 62 69 65 } //Chrome is zombie  1
		$a_80_8 = {53 74 61 72 74 69 6e 67 20 61 6e 64 20 69 6e 6a 65 63 74 69 6e 67 20 63 68 72 6f 6d 65 } //Starting and injecting chrome  1
		$a_80_9 = {5b 49 4e 4a 45 43 54 5d 20 69 6e 6a 65 63 74 5f 76 69 61 5f 72 65 6d 6f 74 65 74 68 72 65 61 64 5f 77 6f 77 36 34 } //[INJECT] inject_via_remotethread_wow64  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=3
 
}