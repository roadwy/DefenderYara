
rule Trojan_Win32_Qakbot_AYE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AYE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 e5 00 09 c5 83 a3 f4 53 43 00 00 31 ab f4 53 43 00 5d 81 e0 00 00 00 00 8f 45 fc 33 45 fc 89 5d fc } //1
		$a_01_1 = {83 a3 2c 51 43 00 00 31 8b 2c 51 43 00 8b 4d fc 29 c0 33 04 e4 83 c4 04 c7 83 00 50 43 00 02 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}