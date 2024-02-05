
rule Trojan_Win32_PSWStealer_XZ_MTB{
	meta:
		description = "Trojan:Win32/PSWStealer.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 d8 31 d2 8d 4d 90 01 01 f7 75 90 01 01 8b 45 90 01 01 0f be 34 10 e8 90 01 04 8d 4d 90 01 01 e8 90 01 04 69 c6 90 01 04 30 04 1f 43 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}