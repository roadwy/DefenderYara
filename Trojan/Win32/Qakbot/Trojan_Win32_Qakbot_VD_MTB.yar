
rule Trojan_Win32_Qakbot_VD_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {a1 e4 dc 6a 00 05 d0 3b 03 00 a3 c0 dc 6a 00 a1 74 df 6a 00 } //01 00 
		$a_03_1 = {8b d8 8b 35 90 01 04 33 f1 c7 05 90 01 08 01 35 90 01 04 a1 90 01 04 8b 0d 90 01 04 89 08 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}