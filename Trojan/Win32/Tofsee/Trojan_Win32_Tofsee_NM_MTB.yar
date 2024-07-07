
rule Trojan_Win32_Tofsee_NM_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 55 d8 83 c2 01 89 55 d8 8b 45 d8 3b 45 cc 7d 34 81 7d cc 69 04 00 00 75 11 c7 45 d4 00 00 00 00 8b 4d d4 51 ff 15 90 01 04 8b 55 d0 03 55 d8 0f be 1a e8 90 01 04 33 d8 8b 45 d0 03 45 d8 88 18 eb 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}