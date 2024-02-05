
rule Trojan_Win32_Delflob_J{
	meta:
		description = "Trojan:Win32/Delflob.J,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 8d 45 e0 b9 90 01 03 00 8b 15 90 01 03 00 e8 90 01 03 ff 8b 45 e0 e8 90 01 03 ff 50 a1 90 01 03 00 e8 90 01 03 ff 50 e8 90 01 03 ff c7 05 90 01 03 00 90 01 04 90 03 01 01 81 83 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}