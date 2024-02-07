
rule Virus_Win32_Adept_gen_A{
	meta:
		description = "Virus:Win32/Adept.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {b8 b8 7a d9 00 } //01 00 
		$a_01_1 = {6a 02 68 70 ff ff ff } //02 00 
		$a_01_2 = {f7 7d 14 8b 45 10 8a 04 02 30 01 46 3b 75 0c 7c e6 } //02 00 
		$a_01_3 = {53 68 65 6c 6c 42 6f 74 52 } //00 00  ShellBotR
	condition:
		any of ($a_*)
 
}