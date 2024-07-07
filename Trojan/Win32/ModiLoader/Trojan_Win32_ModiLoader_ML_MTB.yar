
rule Trojan_Win32_ModiLoader_ML_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.ML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 15 e4 2b 61 00 42 8d 44 10 ff 50 a1 e4 2b 61 00 8a 04 07 5a 88 02 ff 05 e4 2b 61 00 4b 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}