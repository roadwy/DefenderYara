
rule Backdoor_Win32_Rbot_gen_F{
	meta:
		description = "Backdoor:Win32/Rbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {68 30 75 00 00 68 90 01 06 ff 15 90 01 04 50 ff 15 90 01 04 3d 02 01 00 00 75 90 00 } //01 00 
		$a_02_1 = {eb 35 81 bd a8 00 00 00 8b 00 00 00 75 0e ff 75 fc ff 75 f8 90 03 01 01 53 56 e8 90 01 04 eb 18 81 bd a8 00 00 00 bd 01 00 00 75 12 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}