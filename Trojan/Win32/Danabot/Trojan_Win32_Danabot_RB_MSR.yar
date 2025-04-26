
rule Trojan_Win32_Danabot_RB_MSR{
	meta:
		description = "Trojan:Win32/Danabot.RB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 44 29 eb 88 c4 c0 e8 04 75 ?? 88 e0 24 0f 75 ?? 49 75 } //1
		$a_00_1 = {83 eb 02 83 e9 04 8b 45 0c 8b 55 10 81 e0 ff 00 00 00 33 d2 8b 04 85 62 e1 54 00 89 01 8b 45 0c 8b 55 10 0f ac d0 08 c1 ea 08 89 45 0c 89 55 10 83 fb 02 7d } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}