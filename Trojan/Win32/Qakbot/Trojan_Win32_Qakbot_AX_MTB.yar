
rule Trojan_Win32_Qakbot_AX_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 8b 75 10 57 8b f8 85 f6 74 0d 2b d0 8a 0c 3a 88 0f 47 83 ee 01 75 } //4
		$a_01_1 = {0b 01 0e 00 00 d8 00 00 00 9c 04 00 00 00 00 00 60 e7 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}