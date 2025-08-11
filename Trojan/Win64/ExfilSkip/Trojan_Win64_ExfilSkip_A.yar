
rule Trojan_Win64_ExfilSkip_A{
	meta:
		description = "Trojan:Win64/ExfilSkip.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {75 73 65 72 6e 61 6d 65 40 68 ?? 73 74 20 73 6f 75 72 63 65 5f 64 69 72 20 72 65 6d 6f 74 65 5f 70 61 74 68 } //1
		$a_01_1 = {46 6f 75 6e 64 20 25 64 20 66 69 6c 65 73 20 74 6f 74 61 6c 69 6e 67 20 25 2e 32 66 20 4d 42 20 28 73 6b 69 70 70 65 64 20 25 64 20 66 69 6c 65 73 2c } //1 Found %d files totaling %.2f MB (skipped %d files,
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}