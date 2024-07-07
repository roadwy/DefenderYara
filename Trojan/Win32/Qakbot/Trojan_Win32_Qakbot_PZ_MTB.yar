
rule Trojan_Win32_Qakbot_PZ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 66 3b c0 90 13 bb 04 00 00 00 53 66 3b ed 90 13 5e f7 f6 66 3b db 90 13 0f b6 44 15 90 01 01 33 c8 3a ed 90 13 8b 45 90 01 01 88 4c 05 90 01 01 90 13 8b 45 90 01 01 40 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}