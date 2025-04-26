
rule Trojan_Win32_Dridex_VAM_MSR{
	meta:
		description = "Trojan:Win32/Dridex.VAM!MSR,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 34 01 28 d6 80 c6 20 8b 74 24 14 88 34 06 83 c0 20 8b 7c 24 1c 39 f8 89 44 24 08 72 c7 } //1
		$a_01_1 = {8b 4c 24 14 8a 14 01 80 c2 e0 88 14 01 83 c0 01 8b 74 24 1c 39 f0 89 04 24 74 b9 eb e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}