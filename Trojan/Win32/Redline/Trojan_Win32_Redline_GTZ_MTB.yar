
rule Trojan_Win32_Redline_GTZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.GTZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 f0 0f b6 1c 37 c1 e8 90 01 01 0f be 88 90 01 04 6b c9 90 01 01 b8 90 01 04 f7 e9 01 ca c1 f9 90 01 01 c1 fa 90 01 01 29 d1 c1 e1 90 01 01 31 d9 88 0c 37 83 c6 90 01 01 83 fe 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}