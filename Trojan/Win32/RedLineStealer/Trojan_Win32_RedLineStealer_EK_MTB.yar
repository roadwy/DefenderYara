
rule Trojan_Win32_RedLineStealer_EK_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 04 89 4d fc 8b 45 fc 8b 55 08 89 50 04 90 c9 c2 04 00 } //02 00 
		$a_01_1 = {8b 45 0c 0f b6 10 8b 45 08 88 10 90 } //01 00 
		$a_01_2 = {79 6f 6d 6f 79 63 6c } //01 00  yomoycl
		$a_01_3 = {66 67 6b 79 63 78 64 75 69 78 6f 70 69 63 73 } //00 00  fgkycxduixopics
	condition:
		any of ($a_*)
 
}