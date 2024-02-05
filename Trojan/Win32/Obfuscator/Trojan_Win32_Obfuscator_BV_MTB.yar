
rule Trojan_Win32_Obfuscator_BV_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.BV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {50 51 6a 05 ff 15 90 01 04 83 c4 90 01 01 8b 0d 90 01 04 ff 15 90 01 04 8b 0d 90 01 04 8b 79 0c 8b 51 14 2b fa 8b 15 90 01 04 88 04 17 b8 01 00 00 00 03 c2 0f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}