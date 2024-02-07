
rule Trojan_Win32_Biloky_A{
	meta:
		description = "Trojan:Win32/Biloky.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 25 73 3f 75 73 65 72 3d 25 73 26 75 69 64 3d 25 73 26 6f 73 3d 25 69 } //01 00  /%s?user=%s&uid=%s&os=%i
		$a_03_1 = {8b 47 34 8b 7d f8 2b f0 03 cb 2b f8 83 39 00 89 75 f0 74 90 01 01 8b 41 04 83 f8 08 72 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}