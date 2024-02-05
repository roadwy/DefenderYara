
rule Trojan_Win32_Qakbot_FY_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 } //01 00 
		$a_01_1 = {03 d8 89 5d d8 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82 } //00 00 
	condition:
		any of ($a_*)
 
}