
rule Trojan_Win64_TestZero_A{
	meta:
		description = "Trojan:Win64/TestZero.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {5c 6f 62 6a 5c 52 65 6c 65 ?? 73 65 5c 52 75 6e 50 57 53 5f 6c 69 62 2e 70 64 62 } //1
		$a_01_1 = {43 4c 52 5f 6c 69 62 2e 64 6c 6c } //1 CLR_lib.dll
		$a_01_2 = {52 00 75 00 6e 00 50 00 57 00 53 00 5f 00 6c 00 69 00 62 00 2e 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 } //1 RunPWS_lib.Program
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}