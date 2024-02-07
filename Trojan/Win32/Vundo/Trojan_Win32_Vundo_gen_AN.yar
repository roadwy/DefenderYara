
rule Trojan_Win32_Vundo_gen_AN{
	meta:
		description = "Trojan:Win32/Vundo.gen!AN,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 5f 41 30 30 46 25 58 2e 65 78 65 00 } //01 00 
		$a_01_1 = {00 76 6d 63 5f 70 65 00 } //01 00  瘀捭灟e
		$a_00_2 = {72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 25 73 } //00 00  rundll32.exe "%s
	condition:
		any of ($a_*)
 
}