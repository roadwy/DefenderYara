
rule Backdoor_Win32_Fynloski_AA_MTB{
	meta:
		description = "Backdoor:Win32/Fynloski.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 71 5a 74 46 69 30 48 42 52 4b 6e 74 32 51 4b 32 6a 34 54 79 58 56 71 62 30 7a 4e 57 48 57 57 55 66 2e 64 6c 6c } //01 00 
		$a_02_1 = {89 ff 4b 75 fb 90 0a 5f 00 6a 00 6a 00 6a 00 6a 00 e8 90 01 04 4b 75 f0 90 02 4f bb 90 01 04 89 ff 4b 75 fb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}