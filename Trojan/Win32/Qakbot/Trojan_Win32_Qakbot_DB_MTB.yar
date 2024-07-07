
rule Trojan_Win32_Qakbot_DB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 2b c8 8b 15 90 01 04 2b d1 89 15 90 01 04 a1 90 01 04 05 7c 13 0e 01 a3 90 01 04 8b 0d 90 01 04 03 4d f8 8b 15 90 01 04 89 91 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 03 d8 a1 90 02 04 89 18 a1 90 02 04 03 05 90 02 04 a3 90 02 04 6a 00 e8 90 02 04 03 05 90 02 04 40 8b 15 90 02 04 33 02 a3 90 02 04 a1 90 02 04 8b 15 90 02 04 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 90 02 04 a1 90 02 04 83 c0 04 03 05 90 02 04 a3 90 02 04 8b 45 f8 3b 05 90 02 04 0f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}