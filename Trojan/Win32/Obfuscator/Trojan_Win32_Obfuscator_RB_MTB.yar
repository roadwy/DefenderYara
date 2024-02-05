
rule Trojan_Win32_Obfuscator_RB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 44 24 10 2b 7c 24 10 8b 44 24 34 d1 6c 24 24 29 44 24 14 4d 90 01 06 8b 44 24 28 8b 8c 24 90 01 04 89 38 5f 5e 5d 89 58 04 5b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}