
rule Trojan_Win32_Qakbot_RF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 00 e8 90 01 04 83 c0 04 01 05 90 01 04 6a 00 e8 90 01 04 29 05 90 01 04 83 05 90 01 04 04 90 00 } //1
		$a_03_1 = {2d 00 10 00 00 a3 90 01 04 83 90 01 05 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Qakbot_RF_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 02 6a 00 e8 90 01 04 8b d8 83 c3 04 90 02 28 2b d8 01 5d 90 01 01 83 05 90 01 04 04 8b 45 90 01 01 3b 05 90 01 04 72 90 01 01 a1 90 01 04 03 05 90 01 04 2d 00 10 00 00 83 c0 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}