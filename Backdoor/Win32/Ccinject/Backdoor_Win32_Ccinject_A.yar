
rule Backdoor_Win32_Ccinject_A{
	meta:
		description = "Backdoor:Win32/Ccinject.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 44 24 04 20 03 00 00 c7 04 24 00 00 00 00 ff 95 a4 fb ff ff 52 52 89 04 24 ff d6 50 47 81 ff 80 84 1e 00 } //01 00 
		$a_01_1 = {c6 85 39 ff ff ff 69 c6 85 3a ff ff ff 6f c6 85 3b ff ff ff 6e 8d 7d 95 b1 0f f3 aa c6 45 95 56 c6 45 96 69 c6 45 97 72 } //00 00 
	condition:
		any of ($a_*)
 
}