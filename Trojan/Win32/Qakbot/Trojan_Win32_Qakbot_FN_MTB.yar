
rule Trojan_Win32_Qakbot_FN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 18 8b 45 c4 03 45 a4 89 45 a0 8b 45 d8 8b 00 33 45 a0 89 45 a0 6a 00 e8 ?? ?? ?? ?? 8b 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 89 18 6a 00 e8 ?? ?? ?? ?? 8b 5d d8 83 c3 04 2b d8 6a 00 e8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}