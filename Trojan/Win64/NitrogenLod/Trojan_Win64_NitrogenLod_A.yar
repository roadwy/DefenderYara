
rule Trojan_Win64_NitrogenLod_A{
	meta:
		description = "Trojan:Win64/NitrogenLod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_41_0 = {ba 47 65 74 50 72 6f 63 41 49 bb 41 64 64 72 65 73 73 00 01 } //1
		$a_49_1 = {4c 6f 61 64 4c 69 62 72 49 bb 69 62 72 61 72 79 41 00 00 00 01 00 5d 04 00 00 92 45 06 80 5c 2b 00 00 93 45 06 80 00 00 01 00 08 00 15 00 af 01 41 67 65 6e 74 54 65 73 6c 61 2e 43 43 44 48 21 4d } //5120
	condition:
		((#a_41_0  & 1)*1+(#a_49_1  & 1)*5120) >=2
 
}