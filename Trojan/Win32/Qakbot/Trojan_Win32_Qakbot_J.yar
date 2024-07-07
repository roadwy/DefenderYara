
rule Trojan_Win32_Qakbot_J{
	meta:
		description = "Trojan:Win32/Qakbot.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 10 68 26 09 00 00 6a 00 e8 90 01 04 8b d8 a1 90 01 04 8b 00 8b 15 90 01 04 81 c2 8a a5 08 00 03 15 90 01 04 33 c2 03 d8 68 26 09 00 00 6a 00 e8 90 01 04 03 d8 a1 90 01 04 89 18 83 05 90 01 04 04 83 05 90 01 04 04 a1 90 01 04 3b 05 90 01 04 72 98 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}