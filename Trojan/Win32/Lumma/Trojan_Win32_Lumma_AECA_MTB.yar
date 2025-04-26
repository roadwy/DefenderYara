
rule Trojan_Win32_Lumma_AECA_MTB{
	meta:
		description = "Trojan:Win32/Lumma.AECA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c6 74 13 8b 44 24 ?? 8b 4c 24 ?? 8b 54 24 ?? 8a 44 04 ?? 30 04 0a 83 7f 04 00 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}