
rule Trojan_Win32_Pikabot_YZ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.YZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 e8 8b 55 d8 01 02 6a 00 e8 90 01 04 8b 55 cc 03 55 ac 81 ea 90 01 02 00 00 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}