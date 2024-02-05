
rule Trojan_Win32_Obfuscator_XX_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 44 24 0c 30 0c 30 b8 90 01 04 83 f0 90 01 01 83 6c 24 90 01 02 83 7c 24 90 01 02 90 01 06 8b 8c 24 90 01 04 5f 5e 33 cc e8 90 01 04 81 c4 90 01 04 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}