
rule Trojan_Win32_Keylogger_SA{
	meta:
		description = "Trojan:Win32/Keylogger.SA,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 05 00 "
		
	strings :
		$a_80_0 = {43 35 2e 43 6c 69 65 6e 74 2e 4b 4c 2e 70 64 62 } //C5.Client.KL.pdb  05 00 
		$a_80_1 = {67 65 74 5f 41 64 6d 69 6e 49 64 } //get_AdminId  05 00 
		$a_80_2 = {73 65 74 5f 56 69 63 74 69 6d 49 64 } //set_VictimId  05 00 
		$a_80_3 = {73 65 74 5f 43 6f 6d 6d 61 6e 64 49 64 } //set_CommandId  05 00 
		$a_80_4 = {5b 52 69 67 68 74 41 72 72 6f 77 5d } //[RightArrow]  00 00 
	condition:
		any of ($a_*)
 
}