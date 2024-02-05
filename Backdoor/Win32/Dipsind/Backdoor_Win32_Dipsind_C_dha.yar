
rule Backdoor_Win32_Dipsind_C_dha{
	meta:
		description = "Backdoor:Win32/Dipsind.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c0 e8 07 d0 e1 0a c1 8a c8 32 d0 c0 e9 07 d0 e0 0a c8 32 ca 80 f1 63 } //01 00 
		$a_01_1 = {68 a1 86 01 00 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa } //01 00 
		$a_03_2 = {b8 ab aa aa aa 8b b4 24 90 01 01 00 00 00 8b 8c 24 90 01 01 00 00 00 8d 57 02 83 c4 90 01 01 f7 e2 8b 84 24 f8 00 00 00 8b da d1 eb c1 e3 02 85 c0 74 02 89 18 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}