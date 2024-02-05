
rule Backdoor_Win32_Nuwar_gen_A{
	meta:
		description = "Backdoor:Win32/Nuwar.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8d 45 f4 50 8d b3 90 01 03 00 ff 36 e8 90 01 02 00 00 59 50 ff 36 ff 75 f8 ff d7 6a 00 8d 45 f4 50 6a 02 8d 45 fc 50 ff 75 f8 c6 45 fc 0d c6 45 fd 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}