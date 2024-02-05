
rule Trojan_Win32_Redline_ARD_MTB{
	meta:
		description = "Trojan:Win32/Redline.ARD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f 44 d8 89 5d ec 8b 45 e8 83 c0 ff 89 45 e8 89 45 b0 8b 4d e4 83 d1 ff 89 4d e4 89 4d b4 8b 55 e0 } //00 00 
	condition:
		any of ($a_*)
 
}