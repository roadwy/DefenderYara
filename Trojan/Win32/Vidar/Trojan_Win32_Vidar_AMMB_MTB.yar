
rule Trojan_Win32_Vidar_AMMB_MTB{
	meta:
		description = "Trojan:Win32/Vidar.AMMB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_03_0 = {81 ec 08 08 00 00 a1 90 01 04 33 c4 89 84 24 04 08 00 00 81 3d 90 01 04 c7 0f 00 00 90 00 } //02 00 
		$a_03_1 = {30 04 33 83 ff 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}