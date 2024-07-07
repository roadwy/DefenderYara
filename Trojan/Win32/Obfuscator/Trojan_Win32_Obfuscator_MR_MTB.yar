
rule Trojan_Win32_Obfuscator_MR_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 02 83 05 90 02 05 83 90 02 06 a1 90 02 04 3b 90 02 05 90 18 a1 90 02 04 8b 90 02 05 01 10 a1 90 02 04 03 90 02 05 03 90 02 05 8b 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}