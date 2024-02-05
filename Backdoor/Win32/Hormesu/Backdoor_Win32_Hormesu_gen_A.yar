
rule Backdoor_Win32_Hormesu_gen_A{
	meta:
		description = "Backdoor:Win32/Hormesu.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b fb 7e 1b 89 5d fc ff 95 e0 fd ff ff eb 09 b8 01 00 00 00 c3 } //01 00 
		$a_01_1 = {55 43 43 6f 64 65 50 69 65 63 65 43 61 6c 6c 65 72 2e 64 6c 6c 00 75 63 67 6f 00 } //00 00 
	condition:
		any of ($a_*)
 
}