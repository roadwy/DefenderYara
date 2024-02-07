
rule Trojan_Win32_Emotet_AN{
	meta:
		description = "Trojan:Win32/Emotet.AN,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 65 67 77 77 65 72 68 65 72 68 65 72 40 40 21 2e 70 64 62 } //01 00  hegwwerherher@@!.pdb
		$a_01_1 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 77 00 66 00 77 00 2e 00 66 00 77 00 66 00 } //00 00 
	condition:
		any of ($a_*)
 
}