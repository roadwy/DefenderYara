
rule Trojan_WinNT_Keebie_A{
	meta:
		description = "Trojan:WinNT/Keebie.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 6b c9 3b 03 c1 23 d0 8b 45 f4 0f b7 0c 45 90 01 04 2b ca 90 00 } //1
		$a_02_1 = {99 83 e2 03 03 c2 c1 f8 02 89 85 90 01 04 8b 8d 90 01 04 81 e1 03 00 00 80 79 90 01 01 49 83 c9 fc 41 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}