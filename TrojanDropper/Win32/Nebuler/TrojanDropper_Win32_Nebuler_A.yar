
rule TrojanDropper_Win32_Nebuler_A{
	meta:
		description = "TrojanDropper:Win32/Nebuler.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 91 00 50 40 00 33 d0 8b 85 90 01 03 ff 88 90 90 00 50 40 00 8d 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}