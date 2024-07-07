
rule Trojan_Win32_Qakbot_EF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 8b 45 d8 03 45 ac 03 45 e8 03 d8 e8 90 01 04 2b d8 89 5d b0 8b 45 b4 33 45 b0 8b 55 ec 89 02 83 45 e8 04 8b 45 ec 83 c0 04 89 45 ec 8b 45 e8 3b 45 e4 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}