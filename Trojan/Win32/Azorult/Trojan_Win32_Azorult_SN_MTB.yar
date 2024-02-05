
rule Trojan_Win32_Azorult_SN_MTB{
	meta:
		description = "Trojan:Win32/Azorult.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 6a 00 6a 00 90 02 10 53 81 ff 90 01 02 00 00 75 90 01 01 90 02 20 81 3d 90 01 06 00 00 75 90 01 01 90 02 15 8b 15 90 01 04 69 d2 90 01 03 00 89 15 90 01 04 81 05 90 01 03 00 90 01 03 00 81 3d 90 01 03 00 90 01 02 00 00 0f b7 1d 90 01 04 75 90 01 01 90 02 10 30 1c 2e 46 3b f7 7c 90 01 01 5b 5f 5e 5d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}