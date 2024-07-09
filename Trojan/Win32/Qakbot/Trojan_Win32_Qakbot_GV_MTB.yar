
rule Trojan_Win32_Qakbot_GV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 d8 89 18 8b 45 c4 03 45 a4 89 45 a0 [0-0f] 8b d8 03 5d a0 [0-0f] 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 d8 8b 55 a0 89 10 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}