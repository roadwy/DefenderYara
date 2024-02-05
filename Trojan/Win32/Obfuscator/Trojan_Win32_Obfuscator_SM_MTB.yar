
rule Trojan_Win32_Obfuscator_SM_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b c8 03 4d 08 83 e9 90 01 01 90 01 05 03 d8 83 c4 90 01 01 58 c9 90 01 03 c1 c9 90 01 01 c0 c8 90 01 01 c0 c8 90 01 01 34 90 01 01 aa e9 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}