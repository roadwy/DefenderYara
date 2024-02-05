
rule Trojan_Win32_Iceid_SB_MTB{
	meta:
		description = "Trojan:Win32/Iceid.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 8d 05 90 01 04 ff d0 59 83 f8 00 0f 90 0a 50 00 8d 0d 90 01 04 51 6a 90 01 01 83 04 24 90 01 01 68 90 01 02 00 00 83 04 24 90 01 01 68 90 01 02 00 00 83 04 24 90 01 01 6a 00 8d 05 90 01 04 ff d0 59 83 f8 00 0f 90 0a 50 00 90 00 } //01 00 
		$a_03_1 = {89 ec 5d f1 ff 35 90 01 04 c3 ff 35 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}