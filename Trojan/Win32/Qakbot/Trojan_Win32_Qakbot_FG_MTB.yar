
rule Trojan_Win32_Qakbot_FG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 d8 8b 00 33 45 a0 89 45 a0 8b 45 a0 8b 55 d8 89 02 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 83 c3 04 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 89 5d d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}