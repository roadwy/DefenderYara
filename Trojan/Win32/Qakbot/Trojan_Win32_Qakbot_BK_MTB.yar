
rule Trojan_Win32_Qakbot_BK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 5d a0 2b d8 6a 00 e8 90 02 04 2b d8 8b 45 d8 33 18 89 5d a0 6a 00 e8 90 02 04 8b 55 a0 2b d0 8b 45 d8 89 10 6a 00 e8 90 02 04 8b 55 a8 83 c2 04 2b d0 89 55 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 72 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}