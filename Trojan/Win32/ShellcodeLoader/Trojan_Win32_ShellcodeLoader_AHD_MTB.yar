
rule Trojan_Win32_ShellcodeLoader_AHD_MTB{
	meta:
		description = "Trojan:Win32/ShellcodeLoader.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 75 74 65 53 68 65 6c 6c 63 6f 64 65 50 61 79 6c 6f 61 64 } //10 ExecuteShellcodePayload
		$a_01_1 = {44 65 63 72 79 70 74 41 6e 64 45 78 74 72 61 63 74 50 61 79 6c 6f 61 64 } //20 DecryptAndExtractPayload
		$a_01_2 = {50 61 79 6c 6f 61 64 54 68 72 65 61 64 } //30 PayloadThread
		$a_01_3 = {66 c7 44 24 47 74 75 c6 44 24 49 61 88 54 24 4a c6 44 24 4b 41 88 54 24 4c } //40
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_01_2  & 1)*30+(#a_01_3  & 1)*40) >=100
 
}