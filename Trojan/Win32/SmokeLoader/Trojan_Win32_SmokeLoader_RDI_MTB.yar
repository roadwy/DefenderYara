
rule Trojan_Win32_SmokeLoader_RDI_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4d f0 8b 45 f4 8b f3 d3 ee 03 c3 89 45 ec } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}