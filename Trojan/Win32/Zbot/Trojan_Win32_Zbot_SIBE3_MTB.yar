
rule Trojan_Win32_Zbot_SIBE3_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {50 8b d8 85 c0 90 18 90 90 58 2b f0 50 8b d8 90 18 90 18 51 8b 07 8b c8 40 90 18 8b 06 8a e9 32 c5 fe c1 90 18 88 07 46 90 00 } //1
		$a_02_1 = {50 8b d8 85 c0 90 18 90 90 58 2b f0 50 8b d8 90 18 90 18 51 8b 07 8b c8 40 e8 90 01 04 47 4b 8b c3 59 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}