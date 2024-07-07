
rule Trojan_Win32_SmokeLoader_SE_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c7 04 24 04 00 00 00 8b 44 24 08 83 2c 24 04 01 04 24 8b 04 24 31 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}