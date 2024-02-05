
rule Trojan_Win32_Hancitor_MR_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {2b f2 8b 15 90 02 04 01 35 90 02 04 80 3d 90 02 05 8d 90 02 06 8b 37 90 18 ff 35 90 02 04 69 c0 90 02 04 51 6a 00 50 e8 90 02 04 a3 90 02 04 81 90 02 05 89 90 02 05 89 90 02 05 89 37 8b 90 02 05 8b 90 02 05 8b c1 2b c3 48 48 83 c5 04 a3 90 02 04 81 90 02 05 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}