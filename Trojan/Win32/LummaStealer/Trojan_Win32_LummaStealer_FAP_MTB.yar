
rule Trojan_Win32_LummaStealer_FAP_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.FAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d3 83 e2 1f 8a 0c 29 8b 6c 24 2c 32 0c 28 8b c3 8b 6c 24 60 83 e0 7f 43 32 0c 28 } //4
		$a_01_1 = {8b 44 24 28 8b 54 24 34 32 0c 06 32 0c 16 32 4c 24 12 30 0f 8b 4c 24 58 8b 74 24 54 3b 5c 24 44 72 a6 } //5
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*5) >=9
 
}