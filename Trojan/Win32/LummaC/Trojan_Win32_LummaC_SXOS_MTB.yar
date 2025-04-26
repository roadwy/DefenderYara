
rule Trojan_Win32_LummaC_SXOS_MTB{
	meta:
		description = "Trojan:Win32/LummaC.SXOS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c0 46 89 44 24 0c 83 6c 24 0c 0a 90 83 6c 24 0c 3c 8a 44 24 0c 30 04 2f 83 fb 0f 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}