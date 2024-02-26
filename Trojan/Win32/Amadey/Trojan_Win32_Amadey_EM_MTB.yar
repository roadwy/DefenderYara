
rule Trojan_Win32_Amadey_EM_MTB{
	meta:
		description = "Trojan:Win32/Amadey.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {0f b6 0f 32 cb 66 81 ea 59 53 0f bc d3 d2 d6 80 c1 ef d0 c9 66 81 ca 46 52 66 85 c8 80 c1 16 d2 da 66 0f ca 80 f1 b8 32 d9 89 04 0c } //00 00 
	condition:
		any of ($a_*)
 
}