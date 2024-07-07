
rule Trojan_Win32_Pinkslipbot_RPM_MTB{
	meta:
		description = "Trojan:Win32/Pinkslipbot.RPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 90 01 04 03 45 b4 8b 55 ec 31 02 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 cd 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}