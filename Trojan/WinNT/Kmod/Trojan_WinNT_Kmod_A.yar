
rule Trojan_WinNT_Kmod_A{
	meta:
		description = "Trojan:WinNT/Kmod.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 04 6a 04 53 ff 15 90 01 04 6a 04 6a 04 57 ff 15 90 01 04 c7 45 fc fe ff ff ff 8b 13 a1 90 01 04 39 50 08 77 90 01 01 c7 45 e4 0d 00 00 c0 83 66 1c 00 8b 45 e4 89 46 18 32 d2 8b ce ff 15 90 01 04 8b 45 e4 90 00 } //1
		$a_00_1 = {fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 8b 07 89 04 91 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}