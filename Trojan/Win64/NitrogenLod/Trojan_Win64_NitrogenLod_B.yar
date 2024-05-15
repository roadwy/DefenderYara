
rule Trojan_Win64_NitrogenLod_B{
	meta:
		description = "Trojan:Win64/NitrogenLod.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {49 ba 47 65 74 50 72 6f 63 41 49 90 01 01 41 64 64 72 65 73 73 90 00 } //01 00 
		$a_41_1 = {ba 4c 6f 61 64 4c 69 62 72 49 bb 69 62 72 61 72 79 41 00 00 } //00 01 
	condition:
		any of ($a_*)
 
}