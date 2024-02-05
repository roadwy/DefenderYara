
rule PUA_Win32_InstallCore_M{
	meta:
		description = "PUA:Win32/InstallCore.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {58 59 5a 50 68 52 75 6e 00 54 52 51 e8 07 00 00 00 90 ff d0 83 c4 04 c3 } //00 00 
	condition:
		any of ($a_*)
 
}