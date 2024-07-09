
rule Trojan_Win32_Smokeloader_CCEG_MTB{
	meta:
		description = "Trojan:Win32/Smokeloader.CCEG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b f8 d3 ef 8d 14 03 31 55 ?? 03 7d } //1
		$a_03_1 = {8b 45 f4 31 7d ?? 8b 4d ?? 29 4d ?? 81 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}