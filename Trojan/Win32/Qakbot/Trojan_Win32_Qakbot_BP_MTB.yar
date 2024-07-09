
rule Trojan_Win32_Qakbot_BP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 d8 03 55 b4 2b d0 8b 45 ec 31 10 6a 00 e8 [0-04] 8b d8 8b 45 e8 83 c0 04 03 d8 6a 00 e8 [0-04] 2b d8 6a 00 e8 [0-04] 03 d8 6a 00 e8 [0-04] 2b d8 89 5d e8 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}