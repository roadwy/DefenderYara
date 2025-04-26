
rule Backdoor_Win32_Joanap_E_dha{
	meta:
		description = "Backdoor:Win32/Joanap.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4b 42 44 5f 25 73 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 43 41 54 } //1 %s\KBD_%s_%02d%02d%02d%02d%02d.CAT
		$a_00_1 = {7e 25 6c 64 28 25 6c 64 25 25 29 } //1 ~%ld(%ld%%)
		$a_00_2 = {25 73 5c 6f 65 6d 2a 2e 2a } //1 %s\oem*.*
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Backdoor_Win32_Joanap_E_dha_2{
	meta:
		description = "Backdoor:Win32/Joanap.E!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 73 5c 4b 42 44 5f 25 73 5f 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 25 30 32 64 2e 43 41 54 } //1 %s\KBD_%s_%02d%02d%02d%02d%02d.CAT
		$a_00_1 = {7e 25 6c 64 28 25 6c 64 25 25 29 } //1 ~%ld(%ld%%)
		$a_00_2 = {25 73 5c 6f 65 6d 2a 2e 2a } //1 %s\oem*.*
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}