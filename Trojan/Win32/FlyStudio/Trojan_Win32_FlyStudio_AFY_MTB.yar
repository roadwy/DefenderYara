
rule Trojan_Win32_FlyStudio_AFY_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.AFY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 56 25 ff 00 00 00 6a 00 50 8b f1 6a 00 ff 15 f0 a1 53 00 89 06 8b c6 5e } //01 00 
		$a_01_1 = {8b 44 24 04 56 68 f4 3a 99 00 8b f1 68 ff ff ff 7f 50 6a 00 89 06 ff 15 20 a3 53 00 89 46 04 8b c6 5e } //00 00 
	condition:
		any of ($a_*)
 
}