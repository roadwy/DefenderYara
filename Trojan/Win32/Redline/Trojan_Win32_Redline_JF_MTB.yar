
rule Trojan_Win32_Redline_JF_MTB{
	meta:
		description = "Trojan:Win32/Redline.JF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {89 d8 83 e0 03 0f b6 80 90 01 04 30 83 90 01 04 83 c3 01 81 fb 7e 07 00 00 90 00 } //01 00 
		$a_03_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 90 02 20 5c 00 4d 00 53 00 42 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}