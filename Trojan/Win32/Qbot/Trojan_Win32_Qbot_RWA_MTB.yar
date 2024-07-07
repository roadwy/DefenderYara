
rule Trojan_Win32_Qbot_RWA_MTB{
	meta:
		description = "Trojan:Win32/Qbot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 8a a5 08 00 03 45 90 01 01 8b 15 90 01 04 31 02 a1 90 01 04 83 c0 04 a3 90 01 04 83 45 90 01 01 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qbot_RWA_MTB_2{
	meta:
		description = "Trojan:Win32/Qbot.RWA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {05 8a a5 08 00 03 05 90 01 04 8b 15 90 01 04 31 02 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 6a 90 01 01 e8 90 01 04 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 90 00 } //1
		$a_02_1 = {81 c2 8a a5 08 00 03 55 90 01 01 33 c2 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 68 90 01 04 6a 90 01 01 e8 90 01 04 03 d8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}