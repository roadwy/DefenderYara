
rule Trojan_Win32_SmokeLoader_RDA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 e8 89 7d e8 89 35 ec da 42 00 03 45 c8 33 c7 31 45 fc } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}