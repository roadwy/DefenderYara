
rule Trojan_Win32_Zenpak_GPM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GPM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {01 c2 83 c0 07 40 83 f2 01 01 35 90 01 04 31 d0 01 2d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}