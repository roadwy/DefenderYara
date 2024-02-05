
rule Trojan_Win32_Obfuscator_FY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8a 44 0d d8 30 04 32 83 f9 90 01 03 33 c9 90 01 02 41 42 3b 53 90 01 03 8d 85 90 01 04 50 6a 90 01 01 ff 73 90 01 01 56 ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}