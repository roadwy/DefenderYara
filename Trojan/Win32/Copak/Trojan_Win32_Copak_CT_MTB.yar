
rule Trojan_Win32_Copak_CT_MTB{
	meta:
		description = "Trojan:Win32/Copak.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 1e 81 c0 01 00 00 00 81 e8 90 02 04 81 c6 04 00 00 00 29 d1 21 c9 39 fe 75 df 90 00 } //02 00 
		$a_01_1 = {01 fa 29 d7 31 03 43 39 cb 75 e9 } //00 00 
	condition:
		any of ($a_*)
 
}