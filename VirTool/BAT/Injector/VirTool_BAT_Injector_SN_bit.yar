
rule VirTool_BAT_Injector_SN_bit{
	meta:
		description = "VirTool:BAT/Injector.SN!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {da 02 11 04 91 06 61 90 01 01 11 04 90 01 01 8e b7 5d 91 61 9c 11 04 17 d6 13 04 90 00 } //01 00 
		$a_01_1 = {67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74 00 47 65 74 50 69 78 65 6c 00 67 65 74 5f 52 00 67 65 74 5f 47 00 67 65 74 5f 42 } //01 00 
		$a_03_2 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 90 02 20 2e 00 50 00 6e 00 67 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}