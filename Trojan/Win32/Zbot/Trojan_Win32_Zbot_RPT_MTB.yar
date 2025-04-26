
rule Trojan_Win32_Zbot_RPT_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 ea 18 88 14 3e 8b c3 c1 e8 10 88 44 3e 01 8b 44 24 14 8b cb c1 e9 08 88 4c 3e 02 40 88 5c 3e 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}