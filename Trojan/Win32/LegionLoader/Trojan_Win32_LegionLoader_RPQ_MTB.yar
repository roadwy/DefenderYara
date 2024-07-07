
rule Trojan_Win32_LegionLoader_RPQ_MTB{
	meta:
		description = "Trojan:Win32/LegionLoader.RPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 83 c9 fc 41 85 c9 74 12 83 7d d8 00 7e 0c 8b 55 d8 81 c2 90 01 04 89 55 d8 8b 45 90 90 8b 4d bc 89 08 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}