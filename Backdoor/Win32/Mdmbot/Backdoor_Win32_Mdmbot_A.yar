
rule Backdoor_Win32_Mdmbot_A{
	meta:
		description = "Backdoor:Win32/Mdmbot.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {72 65 64 40 62 6c 75 2e 63 6f 6d 00 5b 53 43 41 0d f1 ff ff } //01 00 
		$a_01_1 = {4e 5d 3a 20 53 63 61 6e 20 6e 6f 74 20 61 63 74 69 76 65 2e 72 da b6 b5 87 37 43 75 72 64 6e 34 49 50 16 25 73 } //01 00 
		$a_01_2 = {74 74 70 3a 2f 2f 64 62 73 7e 5c 16 73 30 5a 1b 76 } //01 00 
		$a_01_3 = {6d 64 6d 2e 65 db 6d 0d b4 78 f8 5c b4 b2 64 6f 77 34 58 50 0d 5f bb fd 20 28 53 50 30 } //00 00 
	condition:
		any of ($a_*)
 
}