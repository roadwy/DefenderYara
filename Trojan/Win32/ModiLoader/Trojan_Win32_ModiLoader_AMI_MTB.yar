
rule Trojan_Win32_ModiLoader_AMI_MTB{
	meta:
		description = "Trojan:Win32/ModiLoader.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b f0 8b dc c6 03 63 c6 43 01 6d c6 43 02 64 c6 43 03 20 c6 43 04 2f c6 43 05 63 c6 43 06 20 c6 43 07 65 c6 43 08 72 c6 43 09 61 c6 43 0a 73 c6 43 0b 65 c6 43 0c 20 c6 43 0d 2f c6 43 0e 46 c6 43 0f 20 8b c6 8b d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_ModiLoader_AMI_MTB_2{
	meta:
		description = "Trojan:Win32/ModiLoader.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 7c 86 46 00 68 74 86 46 00 e8 ?? e5 f9 ff 50 e8 ?? e5 f9 ff a3 60 d6 56 00 c6 44 24 10 b8 c6 44 24 11 c0 c6 44 24 12 40 c6 44 24 13 ?? c6 44 24 14 ?? c6 44 24 15 c3 8d 44 24 04 50 6a 06 8d 44 24 18 50 56 8b 44 24 10 50 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}