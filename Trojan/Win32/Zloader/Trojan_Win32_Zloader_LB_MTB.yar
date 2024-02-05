
rule Trojan_Win32_Zloader_LB_MTB{
	meta:
		description = "Trojan:Win32/Zloader.LB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff 8b 0d 90 01 04 8b 15 90 01 04 89 11 33 c0 5f 5d c3 90 00 } //02 00 
		$a_03_1 = {55 8b ec 57 a1 90 01 04 a3 90 01 04 8b 0d 90 01 04 8b 11 89 15 90 01 04 a1 90 01 04 2d 90 01 02 00 00 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}