
rule Trojan_Win32_Obfuscator_OF_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.OF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 f4 8a 8c 15 90 01 04 30 08 40 ff 4d 14 89 45 f4 90 01 06 8b 45 10 5e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}