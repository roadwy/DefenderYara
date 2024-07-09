
rule Trojan_WinNT_Kernelpatch_C{
	meta:
		description = "Trojan:WinNT/Kernelpatch.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 4d fc ff 8b 17 a1 ?? ?? ?? ?? 39 50 08 77 ?? c7 [0-05] 0d 00 00 c0 e9 ?? ?? ?? ?? 8b 08 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 06 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 83 [0-05] 00 e9 } //1
		$a_03_1 = {5a 00 66 c7 45 ?? 77 00 66 c7 45 ?? 43 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}