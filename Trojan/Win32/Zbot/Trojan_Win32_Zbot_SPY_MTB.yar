
rule Trojan_Win32_Zbot_SPY_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 4b 8b d8 85 c0 90 18 90 90 58 2b f0 50 8b d8 90 18 51 90 18 8b 0f 90 18 8b 06 33 c1 90 18 46 88 07 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}