
rule Trojan_Win32_Obfuscator_XY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 23 13 90 01 02 f7 f9 8b 4c 24 90 01 01 8b 44 24 90 01 01 83 c1 90 01 01 89 4c 24 90 01 01 8a 54 14 90 01 01 30 54 08 90 01 01 3b ee 90 01 06 8b 8c 24 90 01 04 64 89 90 01 05 59 5f 5e 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}