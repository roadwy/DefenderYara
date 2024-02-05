
rule Trojan_Win32_Obfuscator_RQ_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {03 da 89 1d 90 01 04 83 d0 90 01 01 89 44 24 24 a3 90 01 04 8b 44 24 1c 8d 34 56 81 c1 90 01 04 83 c6 90 01 01 03 f7 89 08 83 c0 90 01 01 ff 4c 24 14 89 44 24 1c 8b 44 24 24 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}