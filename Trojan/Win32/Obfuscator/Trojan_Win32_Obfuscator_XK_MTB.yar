
rule Trojan_Win32_Obfuscator_XK_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.XK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {f7 de 83 c1 90 01 01 f7 de 83 ee 90 01 01 8d 76 fe 8d 76 01 29 fe 31 ff 09 f7 c7 43 90 01 05 31 33 83 c3 90 01 01 83 c2 90 01 01 8d 90 01 05 81 ee 90 01 04 ff e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}