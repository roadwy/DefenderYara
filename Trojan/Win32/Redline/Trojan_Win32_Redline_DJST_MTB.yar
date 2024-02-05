
rule Trojan_Win32_Redline_DJST_MTB{
	meta:
		description = "Trojan:Win32/Redline.DJST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {50 8d 45 08 50 e8 90 01 04 8b 45 90 01 01 33 45 90 01 01 68 90 01 04 2b f8 8d 45 90 01 01 50 e8 90 01 04 ff 4d 90 01 01 0f 85 90 00 } //01 00 
		$a_00_1 = {31 08 83 c5 70 c9 c2 08 00 } //00 00 
	condition:
		any of ($a_*)
 
}