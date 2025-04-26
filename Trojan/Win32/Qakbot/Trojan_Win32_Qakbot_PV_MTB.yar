
rule Trojan_Win32_Qakbot_PV_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 66 3b ed 90 13 bb 08 00 00 00 53 5e 3a f6 90 13 f7 f6 8b 45 ?? 0f b6 44 10 ?? 66 3b c0 90 13 33 c8 8b 45 ?? 03 45 ?? 90 13 88 08 90 13 8b 45 ?? 90 13 40 89 45 ?? 8b 45 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}