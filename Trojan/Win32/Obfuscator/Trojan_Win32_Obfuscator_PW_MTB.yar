
rule Trojan_Win32_Obfuscator_PW_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b ff 8a 81 90 01 04 30 04 3a 83 f9 90 01 03 33 c9 90 01 02 41 42 3b d3 90 01 02 8b 85 90 01 04 ff d0 6a 90 01 01 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}