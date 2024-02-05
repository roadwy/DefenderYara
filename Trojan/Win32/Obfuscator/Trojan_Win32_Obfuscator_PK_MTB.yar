
rule Trojan_Win32_Obfuscator_PK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 ff 81 3d 90 01 08 59 90 01 02 57 8d 85 90 01 04 50 57 ff 15 90 01 04 8d 45 84 50 57 ff 15 90 01 04 90 01 02 e8 90 01 04 8b 4d 80 30 04 31 b8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}