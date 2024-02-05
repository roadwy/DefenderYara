
rule Backdoor_Win32_Miniduke_C_dha{
	meta:
		description = "Backdoor:Win32/Miniduke.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {65 6e 63 72 79 70 74 65 64 75 73 65 72 6e 61 6d 65 } //encryptedusername  01 00 
		$a_80_1 = {65 6e 63 72 79 70 74 65 64 70 61 73 73 77 6f 72 64 } //encryptedpassword  01 00 
		$a_80_2 = {66 72 6f 6d 20 6d 6f 7a 5f 6c 6f 67 69 6e 73 } //from moz_logins  02 00 
		$a_80_3 = {5c 62 69 6e 5c 62 6f 74 2e 70 64 62 } //\bin\bot.pdb  02 00 
		$a_80_4 = {5c 4e 49 54 52 4f 5c 53 56 41 5c 47 65 6e 65 72 61 74 69 6f 6e 73 5c } //\NITRO\SVA\Generations\  02 00 
		$a_80_5 = {49 4e 54 45 52 4e 45 54 20 45 58 50 4c 4f 52 45 52 20 37 2e 78 2d 38 2e 78 20 48 54 54 50 50 41 53 53 } //INTERNET EXPLORER 7.x-8.x HTTPPASS  00 00 
	condition:
		any of ($a_*)
 
}