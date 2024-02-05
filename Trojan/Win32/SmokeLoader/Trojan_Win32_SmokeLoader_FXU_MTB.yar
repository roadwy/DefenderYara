
rule Trojan_Win32_SmokeLoader_FXU_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.FXU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 84 30 3b 2d 0b 00 8b 0d 90 01 04 88 04 31 81 3d 90 01 04 92 02 00 00 75 16 68 90 01 04 53 53 ff 15 90 01 04 53 53 53 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}