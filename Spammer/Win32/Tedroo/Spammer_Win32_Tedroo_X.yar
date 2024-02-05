
rule Spammer_Win32_Tedroo_X{
	meta:
		description = "Spammer:Win32/Tedroo.X,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 30 04 cb f8 4b 03 4a 75 e1 03 90 01 01 81 ec 10 01 00 00 56 57 be 90 01 03 f4 a5 a5 66 a5 be 90 01 02 58 56 53 e8 90 01 02 c8 85 c0 59 59 74 5b 33 c0 8a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}