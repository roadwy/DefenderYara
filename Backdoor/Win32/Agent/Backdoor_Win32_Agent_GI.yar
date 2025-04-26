
rule Backdoor_Win32_Agent_GI{
	meta:
		description = "Backdoor:Win32/Agent.GI,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 54 45 4d 50 5c 5c 47 72 6f 75 70 2e 77 61 62 } //1 C:\TEMP\\Group.wab
		$a_01_1 = {8a 07 fe c8 88 04 32 42 4f 3b d1 7c f3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}