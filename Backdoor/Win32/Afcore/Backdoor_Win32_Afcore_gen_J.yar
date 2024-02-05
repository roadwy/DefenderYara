
rule Backdoor_Win32_Afcore_gen_J{
	meta:
		description = "Backdoor:Win32/Afcore.gen!J,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {c6 45 d8 56 c6 45 f4 41 c6 45 e8 46 ff 53 } //01 00 
		$a_02_1 = {83 ec 7c 83 7d 0c 01 74 04 32 c0 eb 3f 56 ff 15 90 01 04 ff 35 90 01 04 8b f0 8d 45 84 a3 90 01 04 8b 45 08 56 89 45 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}