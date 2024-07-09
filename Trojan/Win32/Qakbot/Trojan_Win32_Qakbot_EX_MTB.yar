
rule Trojan_Win32_Qakbot_EX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 6a 00 e8 ?? ?? ?? ?? 8b d8 8b 45 a8 83 c0 04 03 45 a4 03 d8 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}