
rule Backdoor_Win32_Poison_AI{
	meta:
		description = "Backdoor:Win32/Poison.AI,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 6f 4f 6e 45 43 74 20 25 73 3a 25 69 20 48 54 54 50 2f 31 2e 30 } //01 00 
		$a_00_1 = {b8 00 04 40 00 ff d0 6a 00 e8 00 00 00 00 ff 25 00 02 40 00 } //00 00 
	condition:
		any of ($a_*)
 
}