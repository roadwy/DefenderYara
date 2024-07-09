
rule Backdoor_Win32_Joanap_B_dha{
	meta:
		description = "Backdoor:Win32/Joanap.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48 } //1
		$a_03_1 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 ?? ?? 00 00 83 c4 14 83 f8 ff 0f ?? ?? 00 00 00 8d 4c 24 08 51 e8 ?? ?? ff ff 6a 00 68 30 75 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Backdoor_Win32_Joanap_B_dha_2{
	meta:
		description = "Backdoor:Win32/Joanap.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {10 20 30 40 50 60 70 80 90 11 12 13 1a ff ee 48 } //1
		$a_03_1 = {68 30 75 00 00 8d 44 24 0c 6a 04 50 56 c7 44 24 18 00 10 00 00 e8 ?? ?? 00 00 83 c4 14 83 f8 ff 0f ?? ?? 00 00 00 8d 4c 24 08 51 e8 ?? ?? ff ff 6a 00 68 30 75 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}