
rule PWS_Win32_Populf_C_dll{
	meta:
		description = "PWS:Win32/Populf.C!dll,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 04 6a 00 6a 00 6a 00 8b 45 fc e8 90 01 02 fc ff 50 8d 45 98 e8 48 fe ff ff 8b 45 98 e8 90 01 02 fc ff 50 8b 45 f4 50 e8 90 01 02 fd ff 90 00 } //01 00 
		$a_02_1 = {fd ff b9 01 00 00 00 33 d2 b8 02 00 00 00 e8 c9 fe ff ff 33 c9 33 d2 b8 04 00 00 00 e8 bb fe ff ff 83 3d 90 01 02 43 00 03 74 0e 83 3d 90 01 02 43 00 01 74 05 e8 64 fe ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}