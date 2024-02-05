
rule Trojan_Win32_Obfuscator_LZ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.LZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 c3 83 ea 90 01 01 a3 90 01 04 8b 44 24 10 8b 4c 24 24 83 44 24 10 04 81 c1 90 01 04 89 08 8b c6 2b c2 69 f8 90 01 04 81 c7 90 01 04 03 fa 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}