
rule Trojan_Win32_Qakbot_HL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c8 8b 45 90 01 01 66 3b d2 74 90 01 01 8b 45 90 01 01 0f b6 44 10 90 01 01 66 3b db 74 90 01 01 66 89 45 90 01 01 bb 90 01 04 66 3b ff 74 90 01 01 66 89 45 90 01 01 bb 90 01 04 3a c0 74 90 01 01 66 89 45 90 01 01 bb 90 01 04 66 3b c9 74 90 01 01 53 58 3a ff 74 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}