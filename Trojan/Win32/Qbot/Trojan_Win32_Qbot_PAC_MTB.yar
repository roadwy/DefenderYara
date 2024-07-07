
rule Trojan_Win32_Qbot_PAC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 d8 8b 00 03 45 a8 03 d8 6a 00 e8 90 01 04 2b d8 90 02 07 e8 90 01 04 8b d8 8b 45 c4 03 45 a4 03 d8 6a 00 e8 90 01 04 2b d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}