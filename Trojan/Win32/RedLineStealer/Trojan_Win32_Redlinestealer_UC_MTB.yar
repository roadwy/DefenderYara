
rule Trojan_Win32_Redlinestealer_UC_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 11 33 d0 a1 90 01 04 03 45 90 01 01 88 10 e9 90 0a 31 00 0f b6 05 90 01 04 8b 0d 90 01 04 03 4d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}