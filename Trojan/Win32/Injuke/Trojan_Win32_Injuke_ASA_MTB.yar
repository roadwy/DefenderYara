
rule Trojan_Win32_Injuke_ASA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.ASA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {2a 01 00 00 00 be 90 02 04 2d 79 00 00 da 0a 00 73 5b 0d ca 1b f0 78 90 00 } //05 00 
		$a_01_1 = {2a 01 00 00 00 5a 05 7c 00 f7 63 78 00 00 da 0a 00 73 5b 0d ca b3 26 78 } //00 00 
	condition:
		any of ($a_*)
 
}