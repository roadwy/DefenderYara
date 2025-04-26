
rule Trojan_Win32_RedLine_RPG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 06 6b c0 5b 2b c8 c1 e9 02 0f be 81 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}