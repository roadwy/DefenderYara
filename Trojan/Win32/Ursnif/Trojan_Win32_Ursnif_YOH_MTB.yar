
rule Trojan_Win32_Ursnif_YOH_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.YOH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {81 c2 48 a6 00 00 52 8b 45 90 01 01 05 58 a6 00 00 50 6a 00 6a 00 8b 4d 90 01 01 0f b7 91 90 01 04 81 f2 e4 07 00 00 52 6a 00 6a 00 6a 00 8b 45 90 00 } //01 00 
		$a_03_1 = {33 d2 f7 f1 8b 45 d8 0f be 8c 10 90 01 04 8b 55 d8 8b 82 90 01 04 03 c1 8b 4d d8 8b 91 90 01 04 8b 4d d8 0f b6 94 11 90 01 04 03 c2 33 d2 b9 00 01 00 00 f7 f1 8b 45 d8 89 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}