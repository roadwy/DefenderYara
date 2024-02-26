
rule Trojan_Win32_Azorult_RC_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 45 e0 8b 45 f0 33 45 e0 89 45 f0 8b 4d e8 03 4d f4 8a 55 f0 88 11 } //00 00 
	condition:
		any of ($a_*)
 
}