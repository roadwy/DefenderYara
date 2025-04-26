
rule Trojan_Win32_ModiLoader_AMO_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AMO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {85 c0 7e 1a 8a 93 a4 50 40 00 30 16 46 43 81 e3 07 00 00 80 79 05 4b 83 cb f8 43 48 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}