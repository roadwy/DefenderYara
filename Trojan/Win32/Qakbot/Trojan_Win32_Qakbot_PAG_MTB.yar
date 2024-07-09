
rule Trojan_Win32_Qakbot_PAG_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 bb 04 00 00 00 90 13 53 5e 3a ed 90 13 f7 f6 0f b6 44 15 ?? 66 3b d2 90 13 33 c8 8b 45 ?? 90 13 88 4c 05 ?? 90 13 8b 45 ?? eb 00 40 89 45 ?? e9 } //1
		$a_01_1 = {70 72 69 6e 74 } //1 print
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}