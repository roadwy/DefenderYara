
rule Trojan_Win32_Qakbot_PMH_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 c4 03 45 a4 8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 6a 00 e8 [0-04] 8b d8 8b 45 a8 83 c0 04 03 45 a4 03 d8 6a 00 e8 [0-04] 2b d8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}