
rule Trojan_Win32_Pikabot_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 40 0c 53 56 57 8b 70 0c c7 45 a0 6b 00 65 00 c7 45 a4 72 00 6e 00 c7 45 a8 65 00 6c 00 c7 45 ac 33 00 32 00 c7 45 b0 2e 00 64 00 c7 45 b4 6c 00 6c 00 89 4d b8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}