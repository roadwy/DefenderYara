
rule Trojan_Win32_Redline_GJE_MTB{
	meta:
		description = "Trojan:Win32/Redline.GJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {f7 f9 8b 45 08 0f be 04 10 99 b9 90 01 04 f7 f9 8b 55 0c 03 55 fc 0f b6 0a 33 c8 8b 55 0c 03 55 fc 88 0a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}