
rule Backdoor_Win32_Fegrat_A_dha{
	meta:
		description = "Backdoor:Win32/Fegrat.A!dha,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 63 6f 6d 6d 73 2e 70 72 6f 74 65 63 74 65 64 43 68 61 6e 6e 65 6c } //01 00 
		$a_01_1 = {52 65 64 46 6c 61 72 65 2f 72 61 74 2f 6d 6f 64 75 6c 65 73 2f 66 69 6c 65 6d 67 6d 74 2e 64 6f 77 6e 6c 6f 61 64 52 75 6e 6e 65 72 } //01 00 
		$a_01_2 = {52 65 64 46 6c 61 72 65 2f 73 61 6e 64 61 6c 73 2f 73 65 72 76 65 72 2e 72 65 61 64 49 6e 52 65 71 75 65 73 74 } //00 00 
	condition:
		any of ($a_*)
 
}