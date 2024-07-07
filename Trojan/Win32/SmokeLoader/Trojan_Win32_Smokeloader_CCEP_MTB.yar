
rule Trojan_Win32_Smokeloader_CCEP_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 89 45 90 01 01 c7 05 90 01 08 03 55 90 01 01 8b 45 90 01 01 31 45 90 01 01 33 55 90 00 } //1
		$a_03_1 = {01 45 fc 8b 7d 90 01 01 8b 4d 90 01 01 8d 04 3b 31 45 fc d3 ef 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}