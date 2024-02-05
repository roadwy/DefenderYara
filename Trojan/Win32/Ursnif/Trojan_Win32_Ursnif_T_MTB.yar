
rule Trojan_Win32_Ursnif_T_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.T!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 00 ff d3 83 3d 90 01 05 75 90 01 01 8a 85 90 01 04 8b 4d 04 34 90 01 01 88 41 90 01 01 6a 00 ff d3 90 00 } //01 00 
		$a_03_1 = {6a 00 ff d3 6a 00 c6 85 90 01 04 6b ff d3 6a 00 c6 85 90 01 04 65 ff d3 6a 00 c6 85 90 01 04 72 ff d3 6a 00 c6 85 90 01 04 6e ff d3 6a 00 c6 85 90 01 04 65 ff d3 6a 00 c6 85 90 01 04 6c ff d3 6a 00 c6 85 90 01 04 33 ff d3 6a 00 c6 85 90 01 04 32 ff d3 6a 00 c6 85 90 01 04 2e ff d3 6a 00 c6 85 90 01 04 64 ff d3 6a 00 c6 85 90 01 04 6c ff d3 6a 00 c6 85 90 01 04 6c ff d3 6a 00 c6 85 90 01 04 00 ff d3 68 90 01 04 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}