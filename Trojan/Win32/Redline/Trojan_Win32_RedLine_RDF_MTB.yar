
rule Trojan_Win32_RedLine_RDF_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b 4d f8 83 0d ?? ?? ?? ?? ?? 8b c1 c1 e8 05 03 45 ec 03 f3 33 f0 33 75 0c c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 89 75 e0 8b 45 e0 29 45 fc 81 45 f4 ?? ?? ?? ?? ff 4d f0 8b 45 fc } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}