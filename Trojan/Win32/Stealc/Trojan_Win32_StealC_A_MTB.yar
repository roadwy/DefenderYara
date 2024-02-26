
rule Trojan_Win32_StealC_A_MTB{
	meta:
		description = "Trojan:Win32/StealC.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 04 0f 31 45 90 01 01 8b f9 8b 4d 90 01 01 d3 ef 03 7d 90 00 } //02 00 
		$a_03_1 = {c6 05 01 c1 42 00 6c c6 05 fb c0 42 00 6d c6 05 fc c0 42 00 67 c6 05 00 c1 42 00 64 c6 05 03 c1 42 00 90 01 01 c6 05 02 c1 42 00 6c c6 05 ff c0 42 00 2e c6 05 fe c0 42 00 32 c6 05 f8 c0 42 00 6d c6 05 fa c0 42 00 69 c6 05 fd c0 42 00 33 c6 05 f9 c0 42 00 73 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}