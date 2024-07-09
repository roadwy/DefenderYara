
rule Trojan_Win32_Emotet_RF_MSR{
	meta:
		description = "Trojan:Win32/Emotet.RF!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b f0 c1 e0 07 c1 ee 19 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9 } //1
		$a_02_1 = {53 8b 5c 24 10 57 8b 7c 24 18 53 e8 ?? ?? 00 00 8b c8 33 d2 8b c6 f7 f1 8a 04 3e 83 c4 04 8a 14 53 32 c2 88 04 3e 46 3b f5 75 df } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}