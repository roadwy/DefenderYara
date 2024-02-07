
rule TrojanDropper_O97M_Mraitlce_E_MTB{
	meta:
		description = "TrojanDropper:O97M/Mraitlce.E!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {2e 4f 70 65 6e 54 65 78 74 46 69 6c 65 28 90 02 10 2c 20 32 2c 20 54 72 75 65 29 90 00 } //01 00 
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //01 00  CreateObject("WScript.Shell")
		$a_00_2 = {2e 65 78 65 22 } //01 00  .exe"
		$a_00_3 = {57 72 69 74 65 42 79 74 65 73 } //00 00  WriteBytes
	condition:
		any of ($a_*)
 
}