
rule Trojan_Win32_UrSnif_RPT_MTB{
	meta:
		description = "Trojan:Win32/UrSnif.RPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 86 18 01 00 00 01 86 94 00 00 00 8b 46 5c 29 86 ac 00 00 00 8b 8e d4 00 00 00 8b 46 70 31 04 11 83 c2 04 8b 86 dc 00 00 00 01 46 70 8b 86 d0 00 00 00 83 f0 01 29 86 d8 00 00 00 8b 86 d8 00 00 00 01 46 28 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}