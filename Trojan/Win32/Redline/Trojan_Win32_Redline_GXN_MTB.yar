
rule Trojan_Win32_Redline_GXN_MTB{
	meta:
		description = "Trojan:Win32/Redline.GXN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {57 8b 7c 24 90 01 01 39 74 24 90 01 03 80 34 37 90 01 01 6a 00 6a 00 ff 15 90 01 04 8a 04 37 2c 90 01 01 34 90 01 01 04 90 01 01 34 90 01 01 2c 90 01 01 34 90 01 01 2c 90 01 01 34 90 01 01 88 04 37 46 3b 74 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}