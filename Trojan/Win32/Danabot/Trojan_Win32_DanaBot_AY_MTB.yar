
rule Trojan_Win32_DanaBot_AY_MTB{
	meta:
		description = "Trojan:Win32/DanaBot.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c7 d3 e0 8b cf c1 e9 90 01 01 03 4d 90 01 01 03 45 90 01 01 03 d7 33 c1 33 c2 29 45 90 01 01 a1 90 02 20 c7 05 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}