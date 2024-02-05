
rule Trojan_Win32_RecordBreaker_PA_MTB{
	meta:
		description = "Trojan:Win32/RecordBreaker.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {33 d2 b9 04 00 00 00 f7 f1 8b 45 10 0f b6 0c 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //01 00 
		$a_00_1 = {5c 6f 75 74 70 75 74 2e 70 64 62 } //00 00 
		$a_00_2 = {5d 04 00 } //00 f8 
	condition:
		any of ($a_*)
 
}