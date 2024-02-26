
rule Trojan_Win32_ulpm_RDA_MTB{
	meta:
		description = "Trojan:Win32/ulpm.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c8 ba 0a 00 00 00 29 f8 d1 f8 89 d5 99 f7 fd 83 c2 30 } //00 00 
	condition:
		any of ($a_*)
 
}