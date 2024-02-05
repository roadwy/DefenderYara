
rule TrojanDropper_O97M_Wopert{
	meta:
		description = "TrojanDropper:O97M/Wopert,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {56 6c 5a 61 56 30 35 47 55 6c 64 58 62 47 52 56 59 54 46 77 56 31 6c 72 56 54 46 56 62 46 70 59 59 33 70 57 55 30 31 56 4e 56 64 61 56 56 5a 61 55 46 45 39 50 51 3d 3d } //00 00 
	condition:
		any of ($a_*)
 
}