
rule HackTool_BAT_Binder_gen_C{
	meta:
		description = "HackTool:BAT/Binder.gen!C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {16 02 8e b7 17 da 0d 0c 2b 12 02 08 02 08 91 90 03 01 01 06 07 08 90 03 01 01 06 07 8e b7 5d 91 61 9c 08 17 d6 0c 08 09 31 ea 02 90 03 01 01 0a 0b 2b 00 90 03 01 01 06 07 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}