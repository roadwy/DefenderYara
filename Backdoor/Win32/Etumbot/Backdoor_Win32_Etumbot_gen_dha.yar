
rule Backdoor_Win32_Etumbot_gen_dha{
	meta:
		description = "Backdoor:Win32/Etumbot.gen!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {ff ff 52 c6 85 ?? ?? ff ff 55 c6 85 ?? ?? ff ff 4e c6 85 ?? ?? ff ff 20 c6 85 ?? ?? ff ff 45 c6 85 ?? ?? ff ff 52 c6 85 ?? ?? ff ff 52 90 09 08 00 3b c3 75 ?? c6 85 } //1
		$a_02_1 = {f3 ab 66 ab c6 45 ?? 62 c6 45 ?? 36 c6 45 ?? 34 c6 45 ?? 5f c6 45 ?? 6e c6 45 ?? 74 c6 45 ?? 6f c6 45 ?? 70 c6 45 ?? 20 c6 45 ?? 65 c6 45 ?? 72 c6 45 ?? 72 } //1
		$a_02_2 = {66 ab aa c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 55 c6 85 ?? ?? ff ff 53 c6 85 ?? ?? ff ff 25 c6 85 ?? ?? ff ff 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}