
rule Trojan_Win32_Redline_TB_MTB{
	meta:
		description = "Trojan:Win32/Redline.TB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0f be 84 24 90 01 04 83 c8 20 89 44 24 64 e9 90 01 04 0f be 84 24 90 01 04 89 44 24 64 8b 44 24 68 8b 4c 24 64 31 c8 69 c0 93 01 00 01 89 84 24 90 01 04 e9 90 00 } //01 00 
		$a_03_1 = {5c 4d 69 63 72 6f 73 6f 66 74 2e 4e 45 54 5c 46 72 61 6d 65 77 6f 72 6b 5c 90 02 20 5c 4d 53 42 75 69 6c 64 2e 65 78 65 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}