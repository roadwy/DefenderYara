
rule Trojan_O97M_Nooteling_B_dha{
	meta:
		description = "Trojan:O97M/Nooteling.B!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {44 65 63 73 74 61 67 65 5f ?? 20 3d 20 62 36 34 44 65 63 6f 64 65 28 73 74 61 67 65 5f ?? 29 } //1
		$a_00_1 = {73 74 61 67 65 5f 32 20 3d 20 22 41 41 45 41 41 41 44 2f 2f 2f 2f 2f } //1 stage_2 = "AAEAAAD/////
		$a_00_2 = {46 75 6e 63 74 69 6f 6e 20 62 36 34 44 65 63 6f 64 65 28 } //1 Function b64Decode(
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}