
rule Trojan_Win32_Redlinestealer_UD_MTB{
	meta:
		description = "Trojan:Win32/Redlinestealer.UD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 45 f8 33 d2 b9 90 01 04 f7 f1 a1 90 01 04 0f be 0c 10 8b 55 90 01 01 0f b6 82 90 01 04 33 c1 8b 4d 90 01 01 88 81 90 01 04 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}