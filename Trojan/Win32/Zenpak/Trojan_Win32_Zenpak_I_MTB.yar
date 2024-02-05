
rule Trojan_Win32_Zenpak_I_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {89 30 01 3d 90 01 04 40 29 c2 31 1d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}