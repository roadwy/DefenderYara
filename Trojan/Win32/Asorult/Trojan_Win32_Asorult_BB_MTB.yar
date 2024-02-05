
rule Trojan_Win32_Asorult_BB_MTB{
	meta:
		description = "Trojan:Win32/Asorult.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {85 c0 75 14 a1 90 01 04 b9 90 01 04 03 c8 03 c3 8a 14 19 88 14 30 a1 90 01 04 8a 0d 90 01 04 03 c3 03 c6 8a 10 32 d1 43 81 fb da 04 00 00 88 10 7e 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}