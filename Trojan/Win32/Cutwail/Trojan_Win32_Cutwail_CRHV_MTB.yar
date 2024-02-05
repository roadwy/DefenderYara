
rule Trojan_Win32_Cutwail_CRHV_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.CRHV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 e9 03 d1 c1 fa 90 01 01 8b c2 c1 e8 90 01 01 03 c2 8b d0 c1 e2 90 01 01 2b d0 8b c1 2b c2 8a 90 90 28 2b 42 00 32 91 b8 bd 46 00 8b 44 24 10 88 14 01 41 3b 4c 24 14 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}