
rule Trojan_Win32_Graftor_LMC_MTB{
	meta:
		description = "Trojan:Win32/Graftor.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 85 c9 74 ?? ?? ?? 8d 9b 00 00 00 00 30 04 38 8b 8d e8 ec ff ff 40 3b c1 } //20
		$a_03_1 = {8a 47 01 47 84 c0 75 ?? ?? ?? ?? ?? ?? ?? 8d 85 f0 fe ff ff 89 17 48 8a 48 01 40 84 c9 75 ?? 66 8b 0d ?? ?? ?? ?? 8a 15 16 b2 40 00 8d bd f0 fe ff ff 66 89 08 88 50 02 4f 8d a4 24 00 00 00 00 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}