
rule Trojan_Win64_CoralWave_A{
	meta:
		description = "Trojan:Win64/CoralWave.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 5a 4d 41 20 68 65 61 64 65 72 20 69 6e 76 61 6c 69 64 20 70 72 6f 70 65 72 74 69 65 73 3a } //1 LZMA header invalid properties:
		$a_01_1 = {73 72 63 5c 70 65 6c 6f 61 64 2e 72 73 } //1 src\peload.rs
		$a_01_2 = {73 72 63 5c 70 72 69 6e 74 61 62 6c 65 2e 72 73 } //1 src\printable.rs
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}