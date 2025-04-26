
rule Trojan_Win32_Qakbot_AE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d a2 d1 00 00 03 05 [0-04] a3 ?? ?? ?? ?? a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? 6a 01 [0-d0] 6a 01 e8 ?? ?? ?? ?? a1 ?? ?? ?? ?? 03 05 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 31 02 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_AE_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 03 d8 a1 [0-04] 33 18 89 1d [0-04] 6a 00 e8 [0-04] 8b d8 03 1d [0-04] 6a 00 e8 [0-04] 03 d8 a1 [0-04] 89 18 a1 [0-04] 83 c0 04 a3 [0-04] 33 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}