
rule Trojan_Win32_Obfuscator_FV_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.FV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8a 5d 00 8b 44 24 28 83 c4 18 8a 54 14 14 32 da 88 5d 90 01 01 45 48 89 44 24 10 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}