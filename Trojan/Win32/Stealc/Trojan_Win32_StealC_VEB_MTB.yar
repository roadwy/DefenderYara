
rule Trojan_Win32_StealC_VEB_MTB{
	meta:
		description = "Trojan:Win32/StealC.VEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b d0 8b c8 c1 e2 04 03 54 24 34 c1 e9 05 03 4c 24 28 03 c6 33 d0 89 4c 24 1c 89 54 24 10 89 3d 90 01 04 8b 44 24 1c 01 05 90 01 04 8b 0d 90 01 04 89 4c 24 2c 89 7c 24 1c 8b 44 24 2c 01 44 24 1c 8b 44 24 10 33 44 24 1c 89 44 24 1c 8b 54 24 1c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}