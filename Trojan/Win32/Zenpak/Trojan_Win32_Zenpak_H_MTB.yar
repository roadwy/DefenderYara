
rule Trojan_Win32_Zenpak_H_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.H!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 28 8d 05 90 01 04 31 30 8d 05 90 01 04 01 18 8d 05 90 01 04 31 38 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}