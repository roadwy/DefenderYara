
rule Trojan_Win32_RedLine_MBHG_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 14 8b 54 24 10 8b c1 c1 e8 05 03 44 24 20 03 d5 33 c2 03 cf 33 c1 2b f0 8b d6 c1 e2 04 } //01 00 
		$a_01_1 = {8b 7d 08 f6 17 80 37 76 47 e2 } //00 00 
	condition:
		any of ($a_*)
 
}