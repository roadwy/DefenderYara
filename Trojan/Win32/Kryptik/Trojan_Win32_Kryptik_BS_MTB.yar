
rule Trojan_Win32_Kryptik_BS_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {e4 e7 ad 7a c7 44 24 90 01 01 e5 2e cd 5b c7 44 24 90 01 01 9a dc a0 75 81 6c 24 90 01 01 ad 7d d8 77 81 44 24 90 01 01 eb 57 f8 5e 81 44 24 90 01 01 0e 1a 61 2a 81 44 24 90 01 01 b4 c8 b9 65 81 44 24 90 01 01 0a 73 d7 07 81 44 24 90 01 01 ca bb e3 2a a1 90 01 04 a3 90 01 04 ff 90 00 } //01 00 
		$a_00_1 = {30 04 3e 46 3b f3 7c f3 } //00 00 
	condition:
		any of ($a_*)
 
}