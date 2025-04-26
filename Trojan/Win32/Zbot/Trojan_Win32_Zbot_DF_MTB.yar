
rule Trojan_Win32_Zbot_DF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DF!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {90 8b 55 fc 8a 1c 11 80 c3 7a 88 1c 11 8b 55 fc 8a 1c 11 80 c3 fd 88 1c 11 8b 55 fc 80 04 11 03 90 8b 55 fc 8a 1c 11 80 f3 19 88 1c 11 41 3b c8 7c ce } //1
		$a_01_1 = {8a 0c 28 80 f1 80 88 0c 28 8b 4c 24 10 40 3b c1 72 ee } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}