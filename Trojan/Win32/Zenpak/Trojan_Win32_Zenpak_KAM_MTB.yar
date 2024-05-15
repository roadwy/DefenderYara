
rule Trojan_Win32_Zenpak_KAM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.KAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 74 68 68 69 68 72 73 65 74 68 5a 68 6f 68 6e } //01 00  HathhihrsethZhohn
		$a_01_1 = {6c 68 74 77 74 68 64 77 73 74 } //01 00  lhtwthdwst
		$a_01_2 = {67 7c 56 2e 30 74 36 2d 2b 43 2a 50 64 32 2b 57 6b 21 65 2b 2d } //00 00  g|V.0t6-+C*Pd2+Wk!e+-
	condition:
		any of ($a_*)
 
}