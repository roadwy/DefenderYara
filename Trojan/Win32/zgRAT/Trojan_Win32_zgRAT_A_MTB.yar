
rule Trojan_Win32_zgRAT_A_MTB{
	meta:
		description = "Trojan:Win32/zgRAT.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {66 ad 66 83 f0 90 01 01 66 ab 66 83 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}