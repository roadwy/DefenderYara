
rule Trojan_Win32_Zenpak_X_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 38 31 d0 29 c2 b8 } //02 00 
		$a_03_1 = {89 f0 50 8f 05 90 01 04 01 d0 31 d0 89 d8 50 8f 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}