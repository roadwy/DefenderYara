
rule Trojan_Win32_Lumma_AZBA_MTB{
	meta:
		description = "Trojan:Win32/Lumma.AZBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c7 74 0f 8b 44 24 ?? 8b 4c 24 ?? 8a 44 04 ?? 30 04 29 85 f6 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}