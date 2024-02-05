
rule Trojan_Win32_Zegost_PEF_MTB{
	meta:
		description = "Trojan:Win32/Zegost.PEF!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 10 8b c8 c1 e9 18 88 0c 3e 8b c8 c1 e9 10 88 4c 3e 01 8b c8 c1 e9 08 88 4c 3e 02 88 44 3e 03 83 c6 04 ff 44 24 18 8b 44 24 18 3b 44 24 14 72 9e } //00 00 
	condition:
		any of ($a_*)
 
}