
rule Trojan_Win32_Ranumbot_SM_MSR{
	meta:
		description = "Trojan:Win32/Ranumbot.SM!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 69 72 74 65 6f 73 42 6c 6f 63 6c 73 6b } //1 WirteosBloclsk
		$a_01_1 = {8b 4d e4 33 4d ec 89 4d e4 8b 45 e4 29 45 d0 8b 55 e8 2b 55 d8 89 55 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}