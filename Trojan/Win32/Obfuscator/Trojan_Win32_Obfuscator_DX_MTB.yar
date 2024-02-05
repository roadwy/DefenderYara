
rule Trojan_Win32_Obfuscator_DX_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 89 15 90 02 30 a3 90 01 04 8b 0d 90 01 04 81 c1 90 01 04 89 0d 90 01 04 8b 15 90 01 04 03 55 90 01 01 a1 90 01 04 89 82 90 01 04 8b 0d 90 01 04 8b 15 90 01 04 8d 84 0a 90 01 04 03 05 90 01 04 03 05 90 01 04 a3 90 01 04 e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}