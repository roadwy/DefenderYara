
rule Trojan_Win32_RedLine_RDM_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 33 45 08 83 25 ?? ?? ?? ?? 00 2b f8 89 45 0c 8b c7 c1 e0 04 89 45 08 8b 45 ec 01 45 08 83 0d ?? ?? ?? ?? ff 8b c7 c1 e8 05 03 45 e8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 0c 8b 45 fc 03 c7 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}