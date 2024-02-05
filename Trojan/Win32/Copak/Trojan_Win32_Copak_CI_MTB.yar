
rule Trojan_Win32_Copak_CI_MTB{
	meta:
		description = "Trojan:Win32/Copak.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {01 f6 46 31 39 b8 90 02 04 41 01 c0 81 c6 01 00 00 00 39 d9 75 d2 90 00 } //02 00 
		$a_01_1 = {31 0b 4f 01 ff 43 01 fe 01 fe 39 c3 75 e8 } //00 00 
	condition:
		any of ($a_*)
 
}