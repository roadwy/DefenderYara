
rule Trojan_Win32_Obfuscator_KI_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.KI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 90 02 30 c7 45 fc 90 01 04 80 34 01 90 01 01 8b 7d fc 47 89 7d fc 41 89 d3 39 d9 75 dc 05 90 01 04 ff e0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}