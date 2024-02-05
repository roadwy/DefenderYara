
rule Trojan_BAT_Dordty_G_MTB{
	meta:
		description = "Trojan:BAT/Dordty.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_80_0 = {73 65 74 5f 43 68 65 63 6b 46 6f 72 49 6c 6c 65 67 61 6c 43 72 6f 73 73 54 68 72 65 61 64 43 61 6c 6c 73 } //set_CheckForIllegalCrossThreadCalls  01 00 
		$a_80_1 = {73 65 74 5f 43 72 65 64 65 6e 74 69 61 6c 73 } //set_Credentials  01 00 
		$a_80_2 = {67 65 74 5f 43 6f 6d 70 75 74 65 72 } //get_Computer  01 00 
		$a_80_3 = {73 65 74 5f 50 61 73 73 77 6f 72 64 43 68 61 72 } //set_PasswordChar  01 00 
		$a_01_4 = {64 00 69 00 73 00 63 00 6f 00 72 00 64 00 40 00 67 00 6d 00 61 00 69 00 6c 00 } //01 00 
		$a_01_5 = {44 00 69 00 73 00 63 00 6f 00 72 00 64 00 20 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 65 00 74 00 61 00 69 00 6c 00 73 00 } //01 00 
		$a_01_6 = {68 00 74 00 74 00 70 00 73 00 5f 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 } //01 00 
		$a_80_7 = {43 3a 5c 50 72 6f 6a 65 6b 74 20 47 61 6e 64 61 6c 66 5c } //C:\Projekt Gandalf\  00 00 
	condition:
		any of ($a_*)
 
}