
rule Trojan_Win32_Qakbot_EI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 89 45 a4 e8 90 01 04 8b 55 d8 8b 1a 03 5d ec 2b d8 e8 90 01 04 03 d8 8b 45 d8 89 18 8b 45 c8 03 45 a0 03 45 ec 03 45 a4 8b 55 d8 31 02 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}