
rule Spammer_Win32_Tedroo_Q{
	meta:
		description = "Spammer:Win32/Tedroo.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 89 e3 66 8b 45 14 6a 01 61 fe 61 ff d7 8b 4d 10 33 db 38 19 79 00 fc e1 89 b5 02 34 04 34 06 } //00 00 
	condition:
		any of ($a_*)
 
}