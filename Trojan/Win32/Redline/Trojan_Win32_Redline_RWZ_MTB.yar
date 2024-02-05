
rule Trojan_Win32_Redline_RWZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.RWZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 90 01 01 0f be 14 10 69 d2 90 01 04 33 f2 83 f6 90 01 01 03 ce 8b 45 90 01 01 03 45 90 01 01 88 08 0f be 4d 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 2b c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}