
rule Backdoor_Win32_Koceg_gen_F{
	meta:
		description = "Backdoor:Win32/Koceg.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 40 02 83 f8 74 } //01 00 
		$a_01_1 = {0f be 40 01 83 f8 69 } //01 00 
		$a_01_2 = {6a ff 8d 45 f4 50 68 f6 01 00 00 6a 00 e8 } //02 00 
		$a_01_3 = {33 45 0c 8b 4d 08 03 4d fc 88 01 eb d5 } //00 00 
	condition:
		any of ($a_*)
 
}