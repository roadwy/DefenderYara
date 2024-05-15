
rule Trojan_Win32_Zenpak_BX_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.BX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 c2 48 48 01 1d 90 01 04 42 8d 05 90 01 04 01 38 8d 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}