
rule Backdoor_BAT_Bladabindi_KAC_MTB{
	meta:
		description = "Backdoor:BAT/Bladabindi.KAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 08 17 d6 02 07 08 91 03 08 91 6f ?? 00 00 06 9c 00 08 17 d6 0c 08 09 13 04 11 04 31 e2 } //10
		$a_01_1 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 4f 00 6e 00 63 00 65 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
		$a_01_2 = {48 00 41 00 43 00 4b 00 45 00 52 00 } //1 HACKER
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}