
rule Trojan_Win32_Qakbot_FH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 9c 03 45 ec 89 45 a0 8b 45 d8 8b 55 ec 01 10 8b 45 c8 03 45 a0 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } //1
		$a_01_1 = {8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 d8 83 c0 04 89 45 d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}