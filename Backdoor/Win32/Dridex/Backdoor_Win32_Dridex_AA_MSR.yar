
rule Backdoor_Win32_Dridex_AA_MSR{
	meta:
		description = "Backdoor:Win32/Dridex.AA!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 3c 89 44 24 6c 8b 4c 24 68 ba 12 77 b0 0c 29 ca 89 54 24 60 8b 54 24 70 8b 74 24 74 81 c2 50 4a 69 26 83 d6 00 8b 7c 24 60 8a 5c 24 67 89 74 24 74 89 54 24 70 f7 d0 89 44 24 6c 8a 7c 24 4f 30 df 80 f7 d8 8b 44 24 74 8b 54 24 70 01 d2 11 c0 8b 74 24 48 89 44 24 38 8b 44 24 54 8a 1c 06 81 f1 ec 13 94 46 89 54 24 70 8b 54 24 38 89 54 24 74 00 fb 88 5c 24 5b 8b 54 24 44 01 c2 89 54 24 5c 39 f9 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}