
rule Trojan_Win32_UrSnif_RPO_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f af 46 70 89 46 70 8b 8e b4 00 00 00 8b 46 68 31 04 0f 83 c7 04 8b 86 c0 00 00 00 01 46 68 8b 86 04 01 00 00 33 46 0c 2d 90 01 04 01 46 60 8b 86 b8 00 00 00 35 90 01 04 0f af 86 9c 00 00 00 89 86 9c 00 00 00 8b 86 f4 00 00 00 31 86 80 00 00 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}