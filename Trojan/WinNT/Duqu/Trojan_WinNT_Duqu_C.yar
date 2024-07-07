
rule Trojan_WinNT_Duqu_C{
	meta:
		description = "Trojan:WinNT/Duqu.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c0 66 3b c1 73 90 01 01 0f b7 c7 6b c0 28 03 c6 8b 48 08 8b 50 10 3b ca 72 02 8b ca 8b 40 0c 3b d8 72 90 00 } //1
		$a_03_1 = {38 5d 0c 74 90 01 01 68 90 01 04 ff 75 08 e8 90 01 04 3b c3 75 07 b8 01 00 00 c0 eb 2b 53 50 8d 45 90 01 01 50 e8 90 01 04 83 c4 0c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}