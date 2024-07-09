
rule Backdoor_Win32_Agent_OY{
	meta:
		description = "Backdoor:Win32/Agent.OY,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {b0 53 b1 45 88 44 24 ?? 88 44 24 ?? b0 52 88 4c 24 ?? 88 44 24 ?? 88 44 24 } //1
		$a_03_1 = {50 c6 44 24 ?? 55 c6 44 24 ?? 52 c6 44 24 ?? 4c c6 44 24 ?? 44 88 4c 24 ?? c6 44 24 ?? 77 } //1
		$a_00_2 = {47 45 54 20 25 73 20 48 54 54 50 2f 31 2e 31 } //1 GET %s HTTP/1.1
		$a_03_3 = {6a 06 8d 85 ?? ?? ff ff 50 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}