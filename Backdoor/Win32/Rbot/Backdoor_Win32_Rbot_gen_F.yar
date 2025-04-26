
rule Backdoor_Win32_Rbot_gen_F{
	meta:
		description = "Backdoor:Win32/Rbot.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 30 75 00 00 68 ?? ?? ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 3d 02 01 00 00 75 } //1
		$a_02_1 = {eb 35 81 bd a8 00 00 00 8b 00 00 00 75 0e ff 75 fc ff 75 f8 (53|56) e8 ?? ?? ?? ?? eb 18 81 bd a8 00 00 00 bd 01 00 00 75 12 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}