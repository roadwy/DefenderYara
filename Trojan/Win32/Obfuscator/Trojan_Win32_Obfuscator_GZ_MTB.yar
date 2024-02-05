
rule Trojan_Win32_Obfuscator_GZ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.GZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 89 10 e9 90 01 0b b8 90 01 04 50 e8 90 01 04 b8 90 01 04 ba 90 01 04 31 c9 80 34 01 b5 41 39 d1 75 90 01 01 05 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}