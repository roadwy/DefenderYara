
rule Trojan_Win32_SpyStealer_XZ_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.XZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_02_0 = {8b 75 0c 3b 5d 90 01 03 8d 8d 90 01 04 e8 90 01 04 8d 8d 90 01 04 e8 90 01 04 89 d8 31 d2 f7 75 90 01 01 8b 45 90 01 01 0f be 04 10 69 c0 90 01 04 30 04 1e 43 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}