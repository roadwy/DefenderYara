
rule Trojan_Win32_SmokeLoader_SA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 8b 4d 90 01 01 89 45 90 01 01 8d 45 90 01 01 e8 90 01 04 8b 45 90 01 01 33 c3 31 45 90 01 01 89 35 90 01 04 8b 45 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}