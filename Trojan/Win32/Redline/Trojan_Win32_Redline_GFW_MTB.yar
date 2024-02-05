
rule Trojan_Win32_Redline_GFW_MTB{
	meta:
		description = "Trojan:Win32/Redline.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {88 4d 80 0f b6 55 d7 f7 d2 8b 45 b8 33 c2 03 45 ac f7 d8 1b c0 83 c0 90 01 01 66 a3 90 01 04 0f be 45 83 99 52 50 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Redline_GFW_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 90 01 01 0f be 04 10 69 c0 90 01 04 99 bf 90 01 04 f7 ff 25 90 01 04 33 f0 03 ce 8b 55 90 01 01 03 55 90 01 01 88 0a 0f be 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 2b d0 8b 45 90 01 01 03 45 90 01 01 88 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}