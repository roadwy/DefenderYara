
rule Trojan_Win32_Obfuscator_RW_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.RW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 7d a4 8b c3 2b fb 8d 5d ac 2b 5d a8 eb 07 90 01 07 8a 0c 03 8d 40 01 32 4c 07 ff 88 48 ff 4a 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}