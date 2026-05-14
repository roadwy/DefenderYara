
rule Trojan_Win32_Badtile_K_AMTB{
	meta:
		description = "Trojan:Win32/Badtile.K!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 18 8b 74 24 08 8b 7c c1 0c 8b 54 c1 08 31 c9 89 7c 24 0c 33 7c 24 30 89 54 24 70 31 f2 09 fa 8b 54 24 30 0f 95 c1 3b 74 24 70 1b 54 24 0c ba ff 00 00 00 0f 42 ca 40 83 c3 f8 80 f9 01 74 ba } //6
	condition:
		((#a_01_0  & 1)*6) >=6
 
}