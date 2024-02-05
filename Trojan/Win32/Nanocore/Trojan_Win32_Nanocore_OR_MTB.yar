
rule Trojan_Win32_Nanocore_OR_MTB{
	meta:
		description = "Trojan:Win32/Nanocore.OR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 84 0d 60 e2 ff ff 81 f9 90 01 04 74 42 34 69 04 ba 04 63 2c 45 fe c8 2c 3a fe c8 04 ef 04 7f 04 9f fe c0 fe c8 04 1e 2c bf fe c8 34 7b fe c8 fe c0 fe c0 04 5f 34 22 fe c8 04 37 04 27 2c 1a 34 7c fe c0 88 84 0d 60 e2 ff ff 83 c1 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}