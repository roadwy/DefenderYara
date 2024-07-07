
rule Trojan_Win32_Spambot_RPY_MTB{
	meta:
		description = "Trojan:Win32/Spambot.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 c8 8b 45 c8 8b 40 3c 8b 4d f0 8d 44 01 04 89 45 e4 8b 45 e4 0f b7 40 10 8b 4d c8 8b 49 3c 8d 44 01 18 89 45 a0 8b 45 c8 03 45 a0 89 45 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}