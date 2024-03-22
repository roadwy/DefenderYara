
rule Trojan_Win32_XMRig_B_MTB{
	meta:
		description = "Trojan:Win32/XMRig.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {03 c6 89 45 90 01 01 8b c6 d3 e8 03 45 90 01 01 89 45 f4 8b 45 90 01 01 31 45 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}