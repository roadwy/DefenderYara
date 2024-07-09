
rule Trojan_Win32_RedLine_RDH_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c6 d3 e8 89 45 fc 8b 45 d0 01 45 fc 8b 45 fc 33 45 f0 83 25 ?? ?? ?? ?? 00 31 45 f8 8b 45 f8 29 45 f4 81 45 e4 ?? ?? ?? ?? ff 4d e0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}