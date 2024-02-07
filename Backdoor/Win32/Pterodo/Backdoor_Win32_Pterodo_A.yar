
rule Backdoor_Win32_Pterodo_A{
	meta:
		description = "Backdoor:Win32/Pterodo.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 73 66 6f 6c 64 65 72 3d 7b 00 } //01 00 
		$a_01_1 = {63 6f 6d 6d 61 6e 64 3d 7b 00 } //01 00  潣浭湡㵤{
		$a_03_2 = {2e 70 68 70 90 02 06 00 50 4f 53 54 90 00 } //01 00 
		$a_03_3 = {5c 64 65 76 65 6c 6f 70 5c 72 65 61 64 79 5c 90 02 50 5c 77 69 6e 72 65 73 74 6f 72 65 2e 70 64 62 90 00 } //00 00 
		$a_00_4 = {5d 04 00 } //00 0b 
	condition:
		any of ($a_*)
 
}