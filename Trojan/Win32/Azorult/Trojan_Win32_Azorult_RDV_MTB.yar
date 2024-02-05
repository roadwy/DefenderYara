
rule Trojan_Win32_Azorult_RDV_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 90 01 04 0f b7 1d 90 01 04 81 e3 ff 7f 00 00 81 3d 90 01 04 e7 08 00 00 75 90 01 01 6a 00 6a 00 6a 00 e8 90 01 04 30 1c 3e 83 fd 19 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}