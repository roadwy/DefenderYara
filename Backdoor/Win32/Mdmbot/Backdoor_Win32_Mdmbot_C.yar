
rule Backdoor_Win32_Mdmbot_C{
	meta:
		description = "Backdoor:Win32/Mdmbot.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {52 53 44 53 90 01 15 3a 5c 90 02 20 41 75 72 6f 72 61 56 4e 43 5c 56 65 64 69 6f 44 72 69 76 65 72 5c 90 02 10 5c 56 65 64 69 6f 44 72 69 76 65 72 2e 70 64 62 90 00 } //01 00 
		$a_02_1 = {52 53 44 53 90 01 15 3a 5c 90 02 20 41 75 72 6f 72 61 56 4e 43 5c 41 76 63 5c 90 02 10 5c 41 56 43 2e 70 64 62 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}