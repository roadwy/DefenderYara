
rule Trojan_WinNT_Kernelpatch_A{
	meta:
		description = "Trojan:WinNT/Kernelpatch.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 00 89 45 d0 60 f5 61 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 45 dc 8b 00 8b 4d d0 8b 55 d4 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
		$a_02_1 = {83 4d fc ff 8b 17 a1 90 01 04 39 50 08 77 90 01 01 c7 45 e4 0d 00 00 c0 e9 90 01 04 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 65 e4 00 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}