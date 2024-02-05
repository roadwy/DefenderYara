
rule Trojan_Win32_Cutwail_RDA_MTB{
	meta:
		description = "Trojan:Win32/Cutwail.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 04 0a c1 f8 05 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 c1 e0 03 01 d0 c1 e0 02 01 d0 29 c1 89 ca 8b 45 e0 01 d0 0f b6 00 31 f0 88 03 } //00 00 
	condition:
		any of ($a_*)
 
}