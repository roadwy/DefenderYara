
rule Backdoor_Win32_Rbot_gen_G{
	meta:
		description = "Backdoor:Win32/Rbot.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b7 c0 99 b9 01 04 00 00 f7 f9 52 ff 15 90 01 04 90 02 07 68 78 56 34 12 90 09 60 00 90 02 30 c6 45 90 01 01 45 90 00 } //01 00 
	condition:
		any of ($a_*)
 
}