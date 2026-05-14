
rule Trojan_Win32_MarcoStealer_AMC_MTB{
	meta:
		description = "Trojan:Win32/MarcoStealer.AMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {32 47 04 88 47 14 32 57 05 88 57 15 44 32 57 06 44 88 57 16 41 32 ca 44 32 47 07 44 88 47 17 41 32 d8 32 47 08 44 32 d8 88 47 18 32 57 09 44 32 ca 88 57 19 88 4f 1a 88 5f 1b 44 88 5f 1c 44 88 4f 1d } //1
		$a_01_1 = {32 31 37 2e 31 35 36 2e 35 30 2e 32 32 38 } //2 217.156.50.228
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}