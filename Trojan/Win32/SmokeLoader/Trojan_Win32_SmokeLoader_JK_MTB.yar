
rule Trojan_Win32_SmokeLoader_JK_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.JK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 03 45 90 01 01 33 45 90 01 01 89 45 90 01 01 8d 45 90 01 01 50 e8 90 00 } //01 00 
		$a_03_1 = {55 8b ec 8b 45 90 01 01 8b 4d 90 01 01 31 08 5d c2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}