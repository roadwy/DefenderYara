
rule Trojan_Win32_Spystealer_VZ_MTB{
	meta:
		description = "Trojan:Win32/Spystealer.VZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {89 d8 31 d2 8d 8d 90 01 04 f7 75 14 8b 45 08 0f be 34 10 e8 90 01 04 8d 8d 90 01 04 e8 90 01 04 69 c6 90 01 04 30 04 1f 43 eb 90 00 } //0a 00 
		$a_02_1 = {2e 00 00 00 c7 44 24 90 01 01 00 ac 01 00 c7 44 24 90 01 01 20 c0 4b 00 c7 04 24 90 01 04 89 85 54 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}