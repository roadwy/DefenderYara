
rule Trojan_Win32_Gozi_DSK_MTB{
	meta:
		description = "Trojan:Win32/Gozi.DSK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {bd a7 19 67 3b 2b ee 89 2d 90 01 04 2b d1 83 c2 50 66 01 15 90 01 04 8b 15 90 01 04 8b 74 24 10 81 c2 f0 e6 76 01 89 16 81 3d 90 01 04 fa ff 00 00 89 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}