
rule Trojan_Win32_Redline_RAX_MTB{
	meta:
		description = "Trojan:Win32/Redline.RAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c7 c1 e8 90 01 01 03 45 90 01 01 68 90 01 04 33 45 90 01 01 c7 05 90 01 08 31 45 90 01 01 2b 75 90 01 01 8d 45 90 01 01 50 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}