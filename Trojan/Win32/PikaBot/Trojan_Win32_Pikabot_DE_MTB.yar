
rule Trojan_Win32_Pikabot_DE_MTB{
	meta:
		description = "Trojan:Win32/Pikabot.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 cc 03 55 ac 81 ea 53 37 02 00 03 55 e8 2b d0 8b 45 d8 31 10 83 45 e8 04 83 45 d8 04 8b 45 e8 3b 45 d4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}