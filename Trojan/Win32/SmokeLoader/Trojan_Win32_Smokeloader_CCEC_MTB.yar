
rule Trojan_Win32_Smokeloader_CCEC_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {03 c3 8b c8 8b 45 ?? 31 45 ?? 33 4d } //1
		$a_03_1 = {d3 e8 03 c7 33 c2 31 45 ?? 8b 45 ?? 29 45 ?? 8b 45 ?? 29 45 ?? ff 4d } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}