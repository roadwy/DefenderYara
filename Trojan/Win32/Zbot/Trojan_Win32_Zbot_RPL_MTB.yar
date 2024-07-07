
rule Trojan_Win32_Zbot_RPL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.RPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c4 04 52 56 56 83 2c 24 01 01 14 24 5e 8a 1e 5a 8b f2 5a 83 e9 01 80 f3 f1 c0 c3 06 80 eb 05 8a c2 fe c8 24 01 32 d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}