
rule Backdoor_Win32_Khrat_A_dha{
	meta:
		description = "Backdoor:Win32/Khrat.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 49 4e 54 45 52 2d 43 54 52 49 50 2e 43 4f 4d } //1 .INTER-CTRIP.COM
		$a_01_1 = {2e 64 6c 6c 00 4b 31 00 4b 32 00 4b 33 } //1
		$a_01_2 = {8b 4d 0c 8b 75 08 30 06 46 e2 fb 5e 59 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}