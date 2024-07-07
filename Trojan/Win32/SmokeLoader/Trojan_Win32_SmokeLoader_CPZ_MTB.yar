
rule Trojan_Win32_SmokeLoader_CPZ_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 c1 e8 90 01 01 03 c5 89 44 24 14 8b 44 24 1c 31 44 24 10 8b 4c 24 10 33 4c 24 14 8d 44 24 28 89 4c 24 10 e8 7d fe ff ff 81 44 90 01 06 83 ef 01 8b 4c 24 28 0f 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}