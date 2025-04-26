
rule Trojan_BAT_Bsymem_W_MTB{
	meta:
		description = "Trojan:BAT/Bsymem.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 "
		
	strings :
		$a_80_0 = {42 79 70 61 73 73 53 69 6c 65 6e 74 43 6c 65 61 6e 75 70 } //BypassSilentCleanup  3
		$a_80_1 = {42 79 70 61 73 73 45 76 65 6e 74 76 77 72 } //BypassEventvwr  3
		$a_80_2 = {42 79 70 61 73 73 46 6f 64 68 65 6c 70 65 72 } //BypassFodhelper  3
		$a_80_3 = {2f 52 75 6e 20 2f 54 4e 20 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 44 69 73 6b 43 6c 65 61 6e 75 70 5c 53 69 6c 65 6e 74 43 6c 65 61 6e 75 70 20 2f 49 } ///Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I  3
		$a_80_4 = {55 41 43 20 42 79 70 61 73 73 20 41 70 70 6c 69 63 61 74 69 6f 6e 20 45 78 65 63 75 74 65 64 } //UAC Bypass Application Executed  3
		$a_80_5 = {49 73 52 75 6e 6e 69 6e 67 41 73 4c 6f 63 61 6c 41 64 6d 69 6e } //IsRunningAsLocalAdmin  3
		$a_80_6 = {43 6f 6e 73 65 6e 74 50 72 6f 6d 70 74 42 65 68 61 76 69 6f 72 41 64 6d 69 6e } //ConsentPromptBehaviorAdmin  3
		$a_80_7 = {2f 43 20 70 6f 77 65 72 73 68 65 6c 6c 20 41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 45 78 74 65 6e 73 69 6f 6e 20 2e 65 78 65 20 2d 46 6f 72 63 65 } ///C powershell Add-MpPreference -ExclusionExtension .exe -Force  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3) >=24
 
}