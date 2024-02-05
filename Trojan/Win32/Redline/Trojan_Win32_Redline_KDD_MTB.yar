
rule Trojan_Win32_Redline_KDD_MTB{
	meta:
		description = "Trojan:Win32/Redline.KDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b 45 90 01 01 0f be 0c 10 6b c9 90 01 01 83 f1 90 01 01 8b 55 90 01 01 03 55 90 01 01 0f b6 02 33 c1 8b 4d 90 01 01 03 4d 90 01 01 88 01 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}