
rule Trojan_O97M_Dotraj_V_MTB{
	meta:
		description = "Trojan:O97M/Dotraj.V!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 45 4d 50 22 29 } //01 00  = Environ("TEMP")
		$a_00_1 = {26 20 22 5c 22 20 26 20 22 72 73 72 73 2e 65 78 65 22 2c 20 76 62 48 69 64 65 } //01 00  & "\" & "rsrs.exe", vbHide
		$a_00_2 = {22 68 74 74 70 3a 2f 2f 67 65 2e 74 74 2f 61 70 69 } //00 00  "http://ge.tt/api
	condition:
		any of ($a_*)
 
}