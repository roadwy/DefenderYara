
rule Trojan_BAT_AsyncRAT_AN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 0a d2 61 d2 61 d2 9c } //01 00 
		$a_01_1 = {47 65 74 45 78 70 6f 72 74 65 64 54 79 70 65 73 } //00 00  GetExportedTypes
	condition:
		any of ($a_*)
 
}