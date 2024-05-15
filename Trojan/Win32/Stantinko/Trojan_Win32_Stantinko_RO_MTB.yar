
rule Trojan_Win32_Stantinko_RO_MTB{
	meta:
		description = "Trojan:Win32/Stantinko.RO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 4e 04 2b 0e b8 ab aa aa 2a f7 e9 8b 06 c1 fa 02 8b fa c1 ef 1f 83 c4 20 03 fa 85 c0 } //00 00 
	condition:
		any of ($a_*)
 
}