
rule Trojan_Win32_Zbot_SIBD26_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBD26!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d8 8b d3 56 51 90 18 8b 07 51 8b c8 48 90 18 8b 06 90 18 33 c1 90 18 90 18 51 56 8b f7 88 06 5e 46 59 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}