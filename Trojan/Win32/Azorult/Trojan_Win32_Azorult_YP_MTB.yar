
rule Trojan_Win32_Azorult_YP_MTB{
	meta:
		description = "Trojan:Win32/Azorult.YP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {69 c9 fd 43 03 00 89 0d 90 01 04 81 05 90 01 04 c3 9e 26 00 81 3d 90 01 04 cf 12 00 00 0f b7 1d 90 01 04 75 0a 6a 00 6a 00 ff 15 90 01 04 8b 45 f8 30 1c 06 46 3b f7 7c 8e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}