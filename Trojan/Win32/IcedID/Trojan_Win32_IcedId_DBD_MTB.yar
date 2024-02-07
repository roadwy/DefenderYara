
rule Trojan_Win32_IcedId_DBD_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 6a 00 6a 00 8d 45 90 01 01 50 ff 15 90 01 04 85 c0 75 3f 6a 08 6a 01 6a 00 6a 00 8d 4d 90 1b 00 51 ff 15 90 1b 01 85 c0 90 00 } //01 00 
		$a_81_1 = {34 35 37 38 36 37 75 6a 68 66 67 68 64 68 67 64 67 66 64 67 68 } //00 00  457867ujhfghdhgdgfdgh
	condition:
		any of ($a_*)
 
}