
rule Trojan_Win64_NitrogenLod_B{
	meta:
		description = "Trojan:Win64/NitrogenLod.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 ba 47 65 74 50 72 6f 63 41 49 ?? 41 64 64 72 65 73 73 } //1
		$a_41_1 = {ba 4c 6f 61 64 4c 69 62 72 49 bb 69 62 72 61 72 79 41 00 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_41_1  & 1)*1) >=2
 
}