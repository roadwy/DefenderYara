
rule Trojan_WinNT_Kernelpatch_C{
	meta:
		description = "Trojan:WinNT/Kernelpatch.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 4d fc ff 8b 17 a1 90 01 04 39 50 08 77 90 01 01 c7 90 02 05 0d 00 00 c0 e9 90 01 04 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 90 02 05 00 e9 90 00 } //1
		$a_03_1 = {5a 00 66 c7 45 90 01 01 77 00 66 c7 45 90 01 01 43 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}