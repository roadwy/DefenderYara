
rule Trojan_Win32_Obfuscator_KK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 3e 89 b5 90 01 04 b8 90 01 04 83 f0 90 01 01 83 ad 90 01 05 8b b5 90 01 04 3b f3 90 01 02 8b 4d fc 5f 5e 33 cd 5b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}