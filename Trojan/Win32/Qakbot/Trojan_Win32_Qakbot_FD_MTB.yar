
rule Trojan_Win32_Qakbot_FD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 d8 01 02 8b 45 cc 03 45 ac 2d ?? ?? ?? ?? 03 45 e8 8b 55 d8 31 02 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 0f 82 } //1
		$a_03_1 = {8b d8 8b 45 d8 03 45 b0 03 45 e8 03 d8 6a 00 e8 ?? ?? ?? ?? 2b d8 89 5d b4 8b 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}